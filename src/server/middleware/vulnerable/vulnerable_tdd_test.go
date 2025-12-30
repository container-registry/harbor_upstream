// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vulnerable

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/goharbor/harbor/src/controller/artifact"
	"github.com/goharbor/harbor/src/controller/artifact/processor/image"
	"github.com/goharbor/harbor/src/controller/project"
	"github.com/goharbor/harbor/src/controller/scan"
	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/pkg/accessory"
	accessorymodel "github.com/goharbor/harbor/src/pkg/accessory/model"
	proModels "github.com/goharbor/harbor/src/pkg/project/models"
	"github.com/goharbor/harbor/src/pkg/scan/vuln"
	artifacttesting "github.com/goharbor/harbor/src/testing/controller/artifact"
	projecttesting "github.com/goharbor/harbor/src/testing/controller/project"
	scantesting "github.com/goharbor/harbor/src/testing/controller/scan"
	"github.com/goharbor/harbor/src/testing/mock"
	accessorytesting "github.com/goharbor/harbor/src/testing/pkg/accessory"
)

type VulnerableTDDTestSuite struct {
	suite.Suite

	originalArtifactController artifact.Controller
	artifactController         *artifacttesting.Controller

	originalProjectController project.Controller
	projectController         *projecttesting.Controller

	originalScanController scan.Controller
	scanController         *scantesting.Controller

	originalAccessMgr accessory.Manager
	accessMgr         *accessorytesting.Manager

	checker     *scantesting.Checker
	scanChecker func() scan.Checker

	artifact *artifact.Artifact
	project  *proModels.Project

	next http.Handler
}

func (suite *VulnerableTDDTestSuite) SetupTest() {
	suite.originalArtifactController = artifactController
	suite.artifactController = &artifacttesting.Controller{}
	artifactController = suite.artifactController

	suite.originalProjectController = projectController
	suite.projectController = &projecttesting.Controller{}
	projectController = suite.projectController

	suite.originalAccessMgr = accessory.Mgr
	suite.accessMgr = &accessorytesting.Manager{}
	accessory.Mgr = suite.accessMgr

	suite.originalScanController = scanController
	suite.scanController = &scantesting.Controller{}
	scanController = suite.scanController

	suite.checker = &scantesting.Checker{}
	suite.scanChecker = scanChecker

	scanChecker = func() scan.Checker {
		return suite.checker
	}

	suite.artifact = &artifact.Artifact{}
	suite.artifact.Type = image.ArtifactTypeImage
	suite.artifact.ProjectID = 1
	suite.artifact.RepositoryName = "library/photon"
	suite.artifact.Digest = "digest"

	suite.project = &proModels.Project{
		ProjectID: suite.artifact.ProjectID,
		Name:      "library",
		Metadata: map[string]string{
			proModels.ProMetaPreventVul: "true",
			proModels.ProMetaSeverity:   vuln.High.String(),
		},
	}

	suite.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func (suite *VulnerableTDDTestSuite) TearDownTest() {
	artifactController = suite.originalArtifactController
	projectController = suite.originalProjectController
	scanController = suite.originalScanController
	accessory.Mgr = suite.originalAccessMgr
	scanChecker = suite.scanChecker
}

func (suite *VulnerableTDDTestSuite) makeRequest() *http.Request {
	req := httptest.NewRequest("GET", "/v2/library/photon/manifests/2.0", nil)

	info := lib.ArtifactInfo{
		Repository: "library/photon",
		Reference:  "2.0",
		Tag:        "2.0",
		Digest:     "",
	}

	return req.WithContext(lib.WithArtifactInfo(req.Context(), info))
}

// TestNoScanReportWithPreventVulEnabled tests that when prevent_vul=true and there's no scan report,
// the artifact should be blocked
func (suite *VulnerableTDDTestSuite) TestNoScanReportWithPreventVulEnabled() {
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)
	mock.OnAnything(suite.accessMgr, "List").Return([]accessorymodel.Accessory{}, nil)
	mock.OnAnything(suite.checker, "IsScannable").Return(true, nil)
	mock.OnAnything(suite.scanController, "GetVulnerable").Return(nil, errors.NotFoundError(nil))

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusPreconditionFailed, rr.Code)
	suite.Contains(rr.Body.String(), "current image without vulnerability scanning cannot be pulled")
}

// TestScanPendingWithPreventVulEnabled tests that when prevent_vul=true and scan is pending,
// the artifact should be blocked with a "scanning" error message
func (suite *VulnerableTDDTestSuite) TestScanPendingWithPreventVulEnabled() {
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)
	mock.OnAnything(suite.accessMgr, "List").Return([]accessorymodel.Accessory{}, nil)
	mock.OnAnything(suite.scanController, "GetVulnerable").Return(&scan.Vulnerable{
		ScanStatus: job.PendingStatus.String(),
	}, nil)

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusPreconditionFailed, rr.Code)
	suite.Contains(rr.Body.String(), "is being scanned")
	suite.Contains(rr.Body.String(), "retry later")
}

// TestScanRunningWithPreventVulEnabled tests that when prevent_vul=true and scan is running,
// the artifact should be blocked with a "scanning" error message
func (suite *VulnerableTDDTestSuite) TestScanRunningWithPreventVulEnabled() {
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)
	mock.OnAnything(suite.accessMgr, "List").Return([]accessorymodel.Accessory{}, nil)
	mock.OnAnything(suite.scanController, "GetVulnerable").Return(&scan.Vulnerable{
		ScanStatus: job.RunningStatus.String(),
	}, nil)

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusPreconditionFailed, rr.Code)
	suite.Contains(rr.Body.String(), "is being scanned")
	suite.Contains(rr.Body.String(), "retry later")
}

// TestScanScheduledWithPreventVulEnabled tests that when prevent_vul=true and scan is scheduled,
// the artifact should be blocked with a "scanning" error message
func (suite *VulnerableTDDTestSuite) TestScanScheduledWithPreventVulEnabled() {
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)
	mock.OnAnything(suite.accessMgr, "List").Return([]accessorymodel.Accessory{}, nil)
	mock.OnAnything(suite.scanController, "GetVulnerable").Return(&scan.Vulnerable{
		ScanStatus: job.ScheduledStatus.String(),
	}, nil)

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusPreconditionFailed, rr.Code)
	suite.Contains(rr.Body.String(), "is being scanned")
	suite.Contains(rr.Body.String(), "retry later")
}

// TestScanErrorWithPreventVulEnabled tests that when prevent_vul=true and scan failed with Error,
// the artifact should be blocked with a "scan failed" error message
func (suite *VulnerableTDDTestSuite) TestScanErrorWithPreventVulEnabled() {
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)
	mock.OnAnything(suite.accessMgr, "List").Return([]accessorymodel.Accessory{}, nil)
	mock.OnAnything(suite.scanController, "GetVulnerable").Return(&scan.Vulnerable{
		ScanStatus: job.ErrorStatus.String(),
	}, nil)

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusPreconditionFailed, rr.Code)
	suite.Contains(rr.Body.String(), "scan Error")
	suite.Contains(rr.Body.String(), "cannot be pulled")
}

// TestScanStoppedWithPreventVulEnabled tests that when prevent_vul=true and scan was stopped,
// the artifact should be blocked with a "scan stopped" error message
func (suite *VulnerableTDDTestSuite) TestScanStoppedWithPreventVulEnabled() {
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)
	mock.OnAnything(suite.accessMgr, "List").Return([]accessorymodel.Accessory{}, nil)
	mock.OnAnything(suite.scanController, "GetVulnerable").Return(&scan.Vulnerable{
		ScanStatus: job.StoppedStatus.String(),
	}, nil)

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusPreconditionFailed, rr.Code)
	suite.Contains(rr.Body.String(), "scan Stopped")
	suite.Contains(rr.Body.String(), "cannot be pulled")
}

// TestNoScanReportWithPreventVulDisabled tests that when prevent_vul=false and there's no scan report,
// the artifact should be allowed
func (suite *VulnerableTDDTestSuite) TestNoScanReportWithPreventVulDisabled() {
	suite.project.Metadata[proModels.ProMetaPreventVul] = "false"
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusOK, rr.Code)
}

// TestScannedBelowThreshold tests that when an artifact is scanned with vulnerabilities
// below the project severity threshold, it should be allowed
func (suite *VulnerableTDDTestSuite) TestScannedBelowThreshold() {
	low := vuln.Low
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)
	mock.OnAnything(suite.accessMgr, "List").Return([]accessorymodel.Accessory{}, nil)
	mock.OnAnything(suite.scanController, "GetVulnerable").Return(&scan.Vulnerable{
		ScanStatus:           job.SuccessStatus.String(),
		Severity:             &low,
		VulnerabilitiesCount: 1,
	}, nil)

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusOK, rr.Code)
}

// TestScannedAboveThreshold tests that when an artifact is scanned with vulnerabilities
// at or above the project severity threshold, it should be blocked
func (suite *VulnerableTDDTestSuite) TestScannedAboveThreshold() {
	critical := vuln.Critical
	mock.OnAnything(suite.artifactController, "GetByReference").Return(suite.artifact, nil)
	mock.OnAnything(suite.projectController, "Get").Return(suite.project, nil)
	mock.OnAnything(suite.accessMgr, "List").Return([]accessorymodel.Accessory{}, nil)
	mock.OnAnything(suite.scanController, "GetVulnerable").Return(&scan.Vulnerable{
		ScanStatus:           job.SuccessStatus.String(),
		Severity:             &critical,
		VulnerabilitiesCount: 2,
	}, nil)

	req := suite.makeRequest()
	rr := httptest.NewRecorder()

	Middleware()(suite.next).ServeHTTP(rr, req)
	suite.Equal(http.StatusPreconditionFailed, rr.Code)
	suite.Contains(rr.Body.String(), "current image with 2 vulnerabilities cannot be pulled")
}

func TestVulnerableTDDTestSuite(t *testing.T) {
	suite.Run(t, &VulnerableTDDTestSuite{})
}

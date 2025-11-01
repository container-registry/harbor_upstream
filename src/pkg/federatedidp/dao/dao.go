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

package dao

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/federatedidp/model"
	"github.com/golang-jwt/jwt/v5"
)

// DAO defines the interface to access the federatedidp data model
type DAO interface {
	// Create ...
	Create(ctx context.Context, r *model.FederatedIdp) (int64, error)

	// Update ...
	Update(ctx context.Context, r *model.FederatedIdp, props ...string) error

	// Get ...
	Get(ctx context.Context, id int64) (*model.FederatedIdp, error)

	// GetIdpByIssuer ...
	GetIdpByIssuer(ctx context.Context, issuer string) (*model.FederatedIdp, error)

	// GetTopMatchedRobot ...
	GetTopMatchedRobot(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error)

	// GetTopMatchedRobot ...
	GetTopMatchedRobots(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error)

	// FindMatchingRobot ...
	FindMatchingRobot(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error)

	// Count returns the total count of federatedidps according to the query
	Count(ctx context.Context, query *q.Query) (total int64, err error)

	// List ...
	List(ctx context.Context, query *q.Query) ([]*model.FederatedIdp, error)

	// Delete ...
	Delete(ctx context.Context, id int64) error

	// DeleteByProjectID ...
	DeleteByProjectID(ctx context.Context, projectID int64) error

	// ListClaims ...
	ListClaims(ctx context.Context, id int64, claim_path string) ([]model.ClaimRule, error)

	// ListClaimsIdpOnly ...
	ListClaimsIdpOnly(ctx context.Context, id int64, claim_path string) ([]model.ClaimRule, error)

	// CreateClaims ...
	CreateClaims(ctx context.Context, idpID int64, claims []model.ClaimRule) error

	// DeleteClaims ...
	DeleteClaims(ctx context.Context, claims []model.ClaimRule) error

	// CreateRobotIdp ...
	CreateRobotIdp(ctx context.Context, r *model.RobotIdentityProvider) (int64, error)

	// DeleteRobotIdpByIdpID ...
	DeleteRobotIdpByIdpID(ctx context.Context, idpID int64) error

	// DeleteRobotIdpByRobotID ...
	DeleteRobotIdpByRobotID(ctx context.Context, robotID int64) error

	// HasRobotIdpByRobotID ...
	HasRobotIdpByRobotID(ctx context.Context, robotID int64) (bool, error)

	// ListRobotIdpByIdpID ...
	ListRobotIdpByIdpID(ctx context.Context, idpID int64) ([]model.RobotIdentityProvider, error)
}

// New creates a default implementation for Dao
func New() DAO {
	return &dao{}
}

type dao struct{}

func (d *dao) Create(ctx context.Context, f *model.FederatedIdp) (int64, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return 0, err
	}
	f.CreationTime = time.Now()
	id, err := ormer.Insert(f)
	if err != nil {
		// Check for unique constraint violation (issuer already exists)
		// log.L.Debug()
		log.Debugf("error in adding federated idp: %v", err)
		return 0, orm.WrapConflictError(err, "federated idp %d:%s already exists, error: %v", f.ProjectID, f.Name, err)
	}
	return id, err
}

func (d *dao) Update(ctx context.Context, f *model.FederatedIdp, props ...string) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	n, err := ormer.Update(f, props...)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.NotFoundError(nil).WithMessagef("federatedidp %d not found", f.ID)
	}
	return nil
}

func (d *dao) Get(ctx context.Context, id int64) (*model.FederatedIdp, error) {
	f := &model.FederatedIdp{
		ID: id,
	}
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := ormer.Read(f); err != nil {
		return nil, orm.WrapNotFoundError(err, "federatedidp %d not found", id)
	}
	return f, nil
}

func (d *dao) GetIdpByIssuer(ctx context.Context, issuer string) (*model.FederatedIdp, error) {
	f := &model.FederatedIdp{
		Issuer: issuer,
	}
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := ormer.Read(f, "issuer"); err != nil {
		return nil, orm.WrapNotFoundError(err, "federatedidp with issuer: %s not found", issuer)
	}
	return f, nil
}

func (d *dao) Count(ctx context.Context, query *q.Query) (int64, error) {
	qs, err := orm.QuerySetterForCount(ctx, &model.FederatedIdp{}, query)
	if err != nil {
		return 0, err
	}
	return qs.Count()
}

func (d *dao) Delete(ctx context.Context, id int64) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	n, err := ormer.Delete(&model.FederatedIdp{
		ID: id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.NotFoundError(nil).WithMessagef("federatedidp %d not found", id)
	}
	return nil
}

func (d *dao) List(ctx context.Context, query *q.Query) ([]*model.FederatedIdp, error) {
	federatedidps := []*model.FederatedIdp{}

	qs, err := orm.QuerySetter(ctx, &model.FederatedIdp{}, query)
	if err != nil {
		return nil, err
	}
	if _, err = qs.All(&federatedidps); err != nil {
		return nil, err
	}
	return federatedidps, nil
}

func (d *dao) DeleteByProjectID(ctx context.Context, projectID int64) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}

	_, err = ormer.Raw("DELETE FROM identity_providers WHERE project_id = ?", projectID).Exec()

	return err
}

func (d *dao) ListClaims(ctx context.Context, id int64, claimPath string) ([]model.ClaimRule, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	qs := ormer.QueryTable(new(model.ClaimRule)).Filter("identity_provider_id", id)

	if claimPath != "" {
		qs = qs.Filter("claim_path", claimPath)
	}

	var rules []model.ClaimRule
	_, err = qs.All(&rules)
	return rules, err
}

func (d *dao) ListClaimsIdpOnly(ctx context.Context, id int64, claimPath string) ([]model.ClaimRule, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	qs := ormer.QueryTable(new(model.ClaimRule)).Filter("identity_provider_id", id).Filter("robot_id", 0)

	if claimPath != "" {
		qs = qs.Filter("claim_path", claimPath)
	}

	var rules []model.ClaimRule
	_, err = qs.All(&rules)
	return rules, err
}

// CreateClaims inserts multiple ClaimRule records into the DB
func (d *dao) CreateClaims(ctx context.Context, idpID int64, claims []model.ClaimRule) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}

	if len(claims) == 0 {
		return nil // nothing to insert
	}

	// validate if the claims are unique
	if err := d.validateUniqueClaims(ctx, idpID, claims); err != nil {
		return err
	}

	// InsertMulti takes (bulkSize, slice)
	_, err = ormer.InsertMulti(len(claims), claims)
	return err
}

// DeleteClaim deletes a claim rule by IdentityProviderID+ClaimPath or RobotID+ClaimPath
func (d *dao) DeleteClaims(ctx context.Context, claims []model.ClaimRule) error {
	// Phase 1: Validation of all claims to be deleted
	var qsList []orm.QuerySeter
	for _, claim := range claims {
		qs, err := d.validateClaimAndGetQuery(ctx, claim)
		if err != nil {
			return err
		}
		qsList = append(qsList, qs)
	}

	// Phase 2: Deletion
	for i, qs := range qsList {
		num, err := qs.Delete()
		if err != nil {
			return err
		}
		if num == 0 {
			return errors.New(nil).WithCode(errors.NotFoundCode).
				WithMessagef("claim rule not found for claim path: %s", claims[i].ClaimPath)
		}
	}
	return nil
}

// GetTopMatchedRobot finds the robot with the most matching claims for the given issuer and token claims.
func (d *dao) GetTopMatchedRobot(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return 0, err
	}

	// Flatten token claims into key/value strings
	claimPairs := map[string]string{}
	for k, v := range tokenClaims {
		claimPairs[k] = fmt.Sprintf("%v", v)
	}

	// If no claims, nothing to do
	if len(claimPairs) == 0 {
		return 0, errors.New("no claims in token")
	}

	// Build dynamic SQL with placeholders
	var args []any
	sql := `
		SELECT robot_id, COUNT(*) AS match_count
		FROM claim_rule
		WHERE identity_provider_id = ?
	`
	args = append(args, issuerID)

	// Add OR conditions for each claim
	sql += " AND ("
	i := 0
	for k, v := range claimPairs {
		if i > 0 {
			sql += " OR "
		}
		sql += "(claim_path = ? AND value = ?)"
		args = append(args, k, v)
		i++
	}
	sql += ")"

	// Group by robot_id and pick the one with most matches
	sql += " GROUP BY robot_id ORDER BY match_count DESC LIMIT 1"

	// Execute query
	var robotID int64
	var matchCount int64
	err = ormer.Raw(sql, args...).QueryRow(&robotID, &matchCount)
	if err == orm.ErrNoRows {
		return 0, errors.NotFoundError(nil).WithMessage("no robot matched the given claims")
	}
	if err != nil {
		return 0, err
	}

	return robotID, nil
}

// gemini version
// GetTopMatchedRobot finds the robot with the most matching claims for the given issuer and token claims.
// It executes a single database query to count matching claims per robot, and returns the ID of the top match.
// Note: For complex aggregation (JOIN, GROUP BY, COUNT, ORDER BY DESC, LIMIT 1) with dynamic WHERE clauses,
// using the ORM's Raw query method remains the most performant and straight-forward approach.
func (d *dao) GetTopMatchedRobots(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return 0, err
	}

	// 1. Flatten token claims into key/value strings for SQL comparison
	claimPairs := map[string]string{}
	for k, v := range tokenClaims {
		// Use fmt.Sprintf("%v", v) to handle various interface{} types and convert to string
		claimPairs[k] = fmt.Sprintf("%v", v)
	}

	// Handle case where no claims are provided to match against
	if len(claimPairs) == 0 {
		return 0, nil // No claims, no matches possible by definition
	}

	// 2. Dynamically build the SQL WHERE clause and parameter list.
	var conditions []string
	var params []interface{}

	// The first parameter for the raw query will be the issuerID, as it's outside the loop.
	params = append(params, issuerID)

	// Build an OR condition for every claim provided in the JWT
	for key, value := range claimPairs {
		// Add the condition for claim path AND claim value.
		conditions = append(conditions, "(cr.claim_path = ? AND cr.value = ?)")
		// Add the key and value as parameters in the correct order.
		params = append(params, key, value)
	}

	// Join all claim conditions using OR
	claimWhereClause := strings.Join(conditions, " OR ")

	// 3. Construct the main SQL query.
	// We query the 'claim_rules' table (cr), filter by identity_provider_id (issuerID) AND the dynamic claims,
	// group by robot_id to count the matches, and order to get the top one.
	sql := fmt.Sprintf(`
		SELECT
			cr.robot_id
		FROM
			claim_rules cr
		WHERE
			cr.identity_provider_id = ? AND (%s)
		GROUP BY
			cr.robot_id
		ORDER BY
			COUNT(cr.robot_id) DESC
	`, claimWhereClause)

	// 4. Execute the raw query and map the result.
	// ormer.Raw() executes the query. The .QueryRow() method is used to get a single row result.
	// The parameters slice contains the issuerID, followed by all key/value pairs for the claims.
	// .Scan(&robotID) maps the result column to the robotID variable.
	// err = ormer.Raw(sql, params...).QueryRow().Scan(&robotID)
	// Execute the Raw query and assign the RawSeter to an explicit variable.
	rawSeter := ormer.Raw(sql, params...)

	// QueryRow() on the RawSeter fetches the single row, and Scan() maps the result to robotID.
	var robotIDs []int64
	num, err := rawSeter.QueryRows(&robotIDs) // ✅ get all rows
	if err != nil {
		// A common error is "no row in result set". We use orm.IsNoRowsError() to check this.
		if orm.ErrNoRows.Error() == err.Error() {
			log.Warningf("no robot matched the given claims: %v", rawSeter)
			return 0, nil // No matching robot found
		}
		return 0, fmt.Errorf("failed to query top matched robot: %w", err)
	}

	if num == 0 {
		log.Warningf("no robots matched your token for issuerID=%d", issuerID) // ✅ clearer log
		return 0, nil
	}

	// Since we used ORDER BY COUNT(...) DESC LIMIT 1, first one is top match
	robotID := robotIDs[0]
	return robotID, nil
}

func (d *dao) FindMatchingRobot(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return 0, err
	}

	// Build VALUES list for SQL
	var valueTuples []string
	for k, v := range tokenClaims {
		valueTuples = append(valueTuples, fmt.Sprintf("('%s', '%v')", k, v))
	}

	if len(valueTuples) == 0 {
		return 0, fmt.Errorf("token has no claims to match")
	}

	valuesClause := strings.Join(valueTuples, ", ")

	// Optimized SQL query
	sql := fmt.Sprintf(`
		SELECT
			cr.robot_id
		FROM
			claim_rules cr
		WHERE
			cr.identity_provider_id = ?
		GROUP BY
			cr.robot_id
		HAVING
			COUNT(*) = SUM(
				CASE
					WHEN (cr.claim_path, cr.value) IN (VALUES %s)
					THEN 1 ELSE 0
				END
			)
		ORDER BY cr.robot_id DESC;
	`, valuesClause)

	var robotIDs []int64
	_, err = ormer.Raw(sql, issuerID).QueryRows(&robotIDs)
	if err != nil {
		if orm.ErrNoRows.Error() == err.Error() {
			log.Warningf("no robots matched your token for issuerID=%d", issuerID)
			return 0, nil
		}
		return 0, fmt.Errorf("failed to query matching robot: %w", err)
	}

	return robotIDs[0], nil
}

// Only with orm no raw sql
// // GetTopMatchedRobot finds the robot with the most matching claims for the given issuer and token claims.
// func (d *dao) GetTopMatchedRobot(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error) {
// 	ormer, err := orm.FromContext(ctx)
// 	if err != nil {
// 		return 0, err
// 	}
//
// 	// Flatten token claims into key/value strings
// 	claimPairs := map[string]string{}
// 	for k, v := range tokenClaims {
// 		claimPairs[k] = fmt.Sprintf("%v", v)
// 	}
// 	if len(claimPairs) == 0 {
// 		return 0, errors.New("no claims in token")
// 	}
//
// 	// Query all rules for this IdP *only for the claim paths we care about*
// 	paths := make([]string, 0, len(claimPairs))
// 	for k := range claimPairs {
// 		paths = append(paths, k)
// 	}
//
// 	var rules []model.ClaimRule
// 	_, err = ormer.QueryTable(new(model.ClaimRule)).
// 		Filter("identity_provider_id", issuerID).
// 		Filter("claim_path__in", paths).
// 		All(&rules)
// 	if err != nil {
// 		return 0, err
// 	}
// 	if len(rules) == 0 {
// 		return 0, errors.NotFoundError(nil).
// 			WithMessagef("no claim rules for issuer %d matched given claims", issuerID)
// 	}
//
// 	// Count matches per robot
// 	matchCount := make(map[int64]int)
// 	for _, r := range rules {
// 		if val, ok := claimPairs[r.ClaimPath]; ok && val == r.Value {
// 			matchCount[r.RobotID]++
// 		}
// 	}
//
// 	// Find robot with max matches
// 	var topRobotID int64
// 	var maxMatches int
// 	for robotID, count := range matchCount {
// 		if count > maxMatches {
// 			topRobotID = robotID
// 			maxMatches = count
// 		}
// 	}
//
// 	if topRobotID == 0 {
// 		return 0, errors.NotFoundError(nil).
// 			WithMessage("no robot matched the given claims")
// 	}
// 	return topRobotID, nil
// }

// very low performant version
// // GetTopMatchedRobot returns the robot_id that matches the most claims for a given issuer.
// func (d *dao) GetTopMatchedRobot(ctx context.Context, issuerID int64, tokenClaims jwt.MapClaims) (int64, error) {
// 	// Step 1: resolve the FederatedIdp by issuer
// 	ormer, err := orm.FromContext(ctx)
// 	if err != nil {
// 		return 0, err
// 	}
//
// 	// Step 2: flatten token claims into key/value strings
// 	claimPairs := map[string]string{}
// 	for k, v := range tokenClaims {
// 		claimPairs[k] = fmt.Sprintf("%v", v)
// 	}
//
// 	// Step 3: query all rules for this IdP
// 	var rules []model.ClaimRule
// 	_, err = ormer.QueryTable(new(model.ClaimRule)).
// 		Filter("identity_provider_id", issuerID).
// 		All(&rules)
// 	if err != nil {
// 		return 0, err
// 	}
//
// 	if len(rules) == 0 {
// 		return 0, errors.NotFoundError(nil).WithMessagef("no claim rules for issuer with id: %d", issuerID)
// 	}
//
// 	// Step 4: count matches per robot_id
// 	matchCount := make(map[int64]int)
// 	for _, r := range rules {
// 		if val, ok := claimPairs[r.ClaimPath]; ok && val == r.Value {
// 			matchCount[r.RobotID]++
// 		}
// 	}
//
// 	// Step 5: pick robot with most matches
// 	var topRobotID int64
// 	var maxMatches int
// 	for robotID, count := range matchCount {
// 		if count > maxMatches {
// 			maxMatches = count
// 			topRobotID = robotID
// 		}
// 	}
//
// 	if topRobotID == 0 {
// 		return 0, errors.NotFoundError(nil).WithMessage("no robot matched the given claims")
// 	}
//
// 	return topRobotID, nil
// }

// CreateRobotIdentityProvider creates a new RobotIdentityProvider record
func (d *dao) CreateRobotIdp(ctx context.Context, r *model.RobotIdentityProvider) (int64, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return 0, err
	}
	r.CreationTime = time.Now()
	id, err := ormer.Insert(r)
	if err != nil {
		return 0, orm.WrapConflictError(err, "robot identity provider %d:%d already exists", r.RobotID, r.IdentityProviderID)
	}
	return id, err
}

// DeleteRobotIdentityProvider deletes a RobotIdentityProvider record
func (d *dao) DeleteRobotIdpByIdpID(ctx context.Context, idpID int64) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}

	_, err = ormer.Raw("DELETE FROM robot_identity_providers WHERE identity_provider_id = ?", idpID).Exec()

	return err
}

// DeleteRobotIdpByRobotID deletes a RobotIdentityProvider record
func (d *dao) DeleteRobotIdpByRobotID(ctx context.Context, robotID int64) error {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}

	_, err = ormer.Raw("DELETE FROM robot_identity_providers WHERE robot_id = ?", robotID).Exec()

	return err
}

// HasRobotIdp checks if a given robot has at least one associated identity provider.
func (d *dao) HasRobotIdpByRobotID(ctx context.Context, robotID int64) (bool, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return false, err
	}

	// Only need to know if at least one record exists
	exists := ormer.QueryTable(new(model.RobotIdentityProvider)).
		Filter("robot_id", robotID).
		Exist()

	return exists, nil
}

// lists all robot_identity_providers associated with the given IDP ID
func (d *dao) ListRobotIdpByIdpID(ctx context.Context, idpID int64) ([]model.RobotIdentityProvider, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var robotIDPs []model.RobotIdentityProvider

	// Fetch all robot IDP records matching the given IDP ID
	_, err = ormer.Raw(
		"SELECT * FROM robot_identity_providers WHERE identity_provider_id = ?",
		idpID,
	).QueryRows(&robotIDPs)

	if err != nil {
		return nil, err
	}

	return robotIDPs, nil
}

func (d *dao) validateClaimAndGetQuery(ctx context.Context, claim model.ClaimRule) (orm.QuerySeter, error) {
	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	if claim.IdentityProviderID == 0 || claim.ClaimPath == "" {
		return nil, errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("invalid claim rule: missing identifiers or claim path")
	}

	qs := ormer.QueryTable(new(model.ClaimRule))

	// apply filter based on which ID is provided
	if claim.RobotID > 0 {
		qs = qs.Filter("robot_id", claim.RobotID)
	} else if claim.IdentityProviderID > 0 {
		qs = qs.Filter("identity_provider_id", claim.IdentityProviderID)
	}

	qs = qs.Filter("claim_path", claim.ClaimPath)

	count, err := qs.Count()
	if err != nil {
		return nil, err
	}

	if count == 0 {
		return nil, errors.New(nil).WithCode(errors.NotFoundCode).
			WithMessage("claim rule not found")
	} else if count > 1 {
		return nil, errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessage("multiple claim rules found, cannot delete, give more specific claim rule")
	}

	return qs, nil
}

// validateUniqueClaims ensures that claim rules being inserted do not violate
// uniqueness constraints across identity providers and robots.
func (d *dao) validateUniqueClaims(ctx context.Context, idpID int64, claims []model.ClaimRule) error {
	if len(claims) == 0 {
		return nil
	}

	ormer, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}

	// 1️⃣ Check for duplicates in the input batch itself
	type key struct {
		IDP     int64
		RobotID int64
		Path    string
		Value   string
	}
	seen := make(map[key]struct{})
	for _, c := range claims {
		k := key{IDP: c.IdentityProviderID, RobotID: c.RobotID, Path: c.ClaimPath, Value: c.Value}
		if _, ok := seen[k]; ok {
			return fmt.Errorf("duplicate claim in input batch for claim_path=%s", c.ClaimPath)
		}
		seen[k] = struct{}{}
	}

	// 2️⃣ Collect all identity_provider IDs and claim paths
	var claimPaths []string
	for _, c := range claims {
		claimPaths = append(claimPaths, c.ClaimPath)
	}

	// 3️⃣ Query existing claims in DB that might conflict
	existingClaims := []model.ClaimRule{}
	_, err = ormer.QueryTable(new(model.ClaimRule)).
		Filter("identity_provider_id", idpID).
		Filter("claim_path__in", claimPaths).
		All(&existingClaims)
	if err != nil {
		return fmt.Errorf("failed to query existing claims: %w", err)
	}

	// 4️⃣ Validate according to rules
	for _, c := range claims {
		for _, e := range existingClaims {
			if c.IdentityProviderID != e.IdentityProviderID || c.ClaimPath != e.ClaimPath {
				continue
			}

			// RULE 1: identity provider owns it
			if e.RobotID == 0 {
				return fmt.Errorf("claim_path '%s' already owned by identity provider %d; cannot be overridden by robot", c.ClaimPath, e.IdentityProviderID)
			}

			// RULE 2: prevent exact duplicate claim for different robots
			if c.Value == e.Value && c.RobotID != e.RobotID {
				return fmt.Errorf("duplicate claim combination found for claim_path '%s' and value '%s'", c.ClaimPath, c.Value)
			}

			// RULE 3: prevent same robot from inserting same claim_path again
			if c.RobotID == e.RobotID {
				return fmt.Errorf("robot %d already has claim_path '%s'", c.RobotID, c.ClaimPath)
			}
		}
	}

	return nil
}

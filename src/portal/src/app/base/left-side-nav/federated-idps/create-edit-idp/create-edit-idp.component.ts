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
import {
    AfterViewChecked,
    Component,
    EventEmitter,
    OnDestroy,
    OnInit,
    Output,
    ViewChild,
} from '@angular/core';
import { NgForm } from '@angular/forms';
import { Subscription, throwError as observableThrowError } from 'rxjs';
import { TranslateService } from '@ngx-translate/core';
import { ErrorHandler } from '../../../../shared/units/error-handler';
import { InlineAlertComponent } from '../../../../shared/components/inline-alert/inline-alert.component';
import {
    clone,
    compareValue,
    CURRENT_BASE_HREF,
    isEmptyObject,
} from '../../../../shared/units/utils';
import { HttpClient } from '@angular/common/http';
import { catchError } from 'rxjs/operators';
import { AppConfigService } from '../../../../services/app-config.service';
import { ClrLoadingState } from '@clr/angular';
import { FederatedIdp } from 'ng-swagger-gen/models';
import { FederatedIdpService } from 'ng-swagger-gen/services';
import { SystemInfo } from 'src/app/shared/services';
import { log } from 'console';
import { id } from '@cds/core/internal';

// const FAKE_JSON_KEY = 'No Change';
// const METADATA_URL = CURRENT_BASE_HREF + '/replication/adapterinfos';
const FIXED_PATTERN_TYPE: string = 'EndpointPatternTypeFix';

@Component({
    selector: 'hbr-create-edit-idp',
    templateUrl: './create-edit-idp.component.html',
    styleUrls: ['./create-edit-idp.component.scss'],
})
export class CreateEditIdpComponent
    implements AfterViewChecked, OnDestroy, OnInit
{
    modalTitle: string;
    // urlDisabled: boolean = false;
    editDisabled: boolean = false;
    createEditIdpOpened: boolean;
    staticBackdrop: boolean = true;
    closable: boolean = false;
    editable: boolean;
    adapterList: string[];
    endpointList: any[] = [];
    target: FederatedIdp = this.initIdp();
    offlineValidation: boolean = false;
    openIDConfigJSON: string;
    jwksKeys: string;
    initVal: FederatedIdp;
    targetForm: NgForm;
    @ViewChild('targetForm') currentForm: NgForm;
    testOngoing: boolean;
    onGoing: boolean;
    idpId: number | string;
    systemInfo: SystemInfo;

    @ViewChild(InlineAlertComponent) inlineAlert: InlineAlertComponent;

    @Output() reload = new EventEmitter<boolean>();
    // Array to store claim data
    claims: { path: string; value: string }[];
    initClaims: { path: string; value: string }[];
    valueChangesSub: Subscription;
    formValues: { [key: string]: string } | any;
    adapterInfo: object;
    showEndpointList: boolean = false;
    endpointOnHover: boolean = false;
    testButtonState: ClrLoadingState = ClrLoadingState.DEFAULT;
    okButtonState: ClrLoadingState = ClrLoadingState.DEFAULT;

    constructor(
        private idpService: FederatedIdpService,
        // private idpDefaultService: FederatedIdpDefaultService,
        private errorHandler: ErrorHandler,
        private translateService: TranslateService,
        private http: HttpClient,
        private appConfigService: AppConfigService
    ) {}

    ngOnInit(): void {
        this.claims = [
            {
                path: 'aud',
                value: this.registryUrl || window.location.hostname,
            },
        ];
        return;
        // this.getAdapters();
        // this.getAdapterInfo();
    }

    selectedEndpoint(endpoint: string) {
        this.targetForm.controls.endpointUrl.reset(endpoint);
        this.showEndpointList = false;
        this.endpointOnHover = false;
    }

    public get registryUrl(): string {
        return this.systemInfo ? this.systemInfo.registry_url : '';
    }

    /**
     * Fetches the OpenID Configuration JSON from the provided URL
     * and stores it as a formatted string in openIDConfigJSON.
     */
    fetchOpenIDConfig() {
        if (this.offlineValidation) {
            return;
        }
        const url = (this.target?.openid_config_url || '').trim();

        // Validate URL strictly before sending request
        if (!url || !url.startsWith('http')) {
            console.warn('⚠️ Invalid OpenID Configuration URL');
            this.inlineAlert.showInlineError(
                'Please provide a valid OpenID Configuration URL.'
            );
            return;
        }

        if (!url.includes('.well-known/openid-configuration')) {
            console.warn(
                '⚠️ Provided URL does not look like an OpenID configuration endpoint.'
            );
            this.inlineAlert.showInlineError(
                'URL must point to a valid ".well-known/openid-configuration" endpoint.'
            );
            return;
        }

        // Update UI loading state
        this.testOngoing = true;
        this.testButtonState = ClrLoadingState.LOADING;
        this.openIDConfigJSON = ''; // clear previous data

        // Call backend via service
        this.idpService
            .PingFederatedIdpOpenIDConfig({
                openidConfigUrl: { openid_config_url: url },
            })
            .subscribe(
                openIDConfigJSON => {
                    // Success callback
                    this.openIDConfigJSON = JSON.stringify(
                        openIDConfigJSON,
                        null,
                        2
                    );

                    console.log(
                        '✅ OpenID Configuration fetched successfully:',
                        openIDConfigJSON
                    );

                    // Extract the 'issuer' key and assign to target
                    if (openIDConfigJSON && openIDConfigJSON.issuer) {
                        this.target.issuer = openIDConfigJSON.issuer;
                        this.claims.push({
                            path: 'iss',
                            value: this.target.issuer,
                        });
                    }

                    // Extract the 'jwks_uri' key and assign to target
                    if (openIDConfigJSON && openIDConfigJSON.issuer) {
                        this.target.jwks_uri = openIDConfigJSON.jwks_uri;
                    }

                    // get the jwks keys
                    // Call backend via service
                    this.idpService
                        .PingFederatedIdpJWKS({
                            jwks: { jwks_uri: this.target.jwks_uri },
                        })
                        .subscribe(
                            jwksKeys => {
                                // Success callback
                                this.jwksKeys = JSON.stringify(
                                    jwksKeys,
                                    null,
                                    2
                                );

                                console.log(
                                    '✅ JWKS Keys fetched successfully:',
                                    jwksKeys
                                );
                            },
                            error => {
                                // Error callback
                                console.error(
                                    '❌ Failed to fetch JWKS Keys:',
                                    error
                                );

                                const message =
                                    error?.status === 404
                                        ? 'JWKS Keys not found at the provided URL.'
                                        : 'Failed to fetch JWKS Keys. Please verify the URL and network access.';

                                this.inlineAlert.showInlineError(message);
                                this.jwksKeys = 'Error fetching JWKS Keys';
                            },
                            () => {
                                // Complete callback (optional)
                                this.testOngoing = false;
                                this.testButtonState = ClrLoadingState.DEFAULT;
                            }
                        );

                    // Optional UI alerts
                    // this.inlineAlert.showInlineSuccess({
                    //     message: 'FEDERATED_IDPS.OPENIDCONFIG_FETCH_SUCCESS',
                    // });
                },
                error => {
                    // Error callback
                    console.error(
                        '❌ Failed to fetch OpenID Configuration:',
                        error
                    );

                    const message =
                        error?.status === 404
                            ? 'OpenID Configuration not found at the provided URL.'
                            : 'Failed to fetch OpenID Configuration. Please verify the URL and network access.';

                    this.inlineAlert.showInlineError(message);
                    this.openIDConfigJSON =
                        'Error fetching OpenID Configuration';
                },
                () => {
                    // Complete callback (optional)
                    this.testOngoing = false;
                    this.testButtonState = ClrLoadingState.DEFAULT;
                }
            );
    }

    blur() {
        if (!this.endpointOnHover) {
            this.showEndpointList = false;
        }
    }

    public get isValid(): boolean {
        return (
            (!this.testOngoing &&
                !this.onGoing &&
                this.targetForm &&
                this.targetForm.valid &&
                this.editable &&
                !compareValue(this.target, this.initVal)) ||
            !compareValue(this.claims, this.initClaims)
        );
    }

    public get inProgress(): boolean {
        return this.onGoing || this.testOngoing;
    }

    setOfflineValidation($event: any) {
        this.target.offline_validation = $event;
    }

    // Function to add a new claim pair
    addClaim(): void {
        this.claims.push({ path: '', value: '' });
    }

    deleteClaim(index: number): void {
        if (this.claims.length === 1) {
            return;
        }
        if (index === 0) {
            return;
        }
        if (this.checkIfMandotaryClaim(index)) {
            return;
        }
        this.claims.splice(index, 1);
    }

    checkIfMandotaryClaim(index: number): boolean {
        if (
            this.claims[index].path === 'aud' ||
            this.claims[index].path === 'iss'
        ) {
            return true;
        }
    }

    ngOnDestroy(): void {
        if (this.valueChangesSub) {
            this.valueChangesSub.unsubscribe();
        }
    }

    initIdp(): FederatedIdp {
        return {
            id: undefined,
            name: '',
            description: '',
            issuer: '',
            supported_algorithms: [],
            claims_supported: [],
            offline_validation: false,
            openid_config_url: '',
            jwks_uri: '',
            jwks_keys: {},
            project_id: undefined,
        };
    }

    open(): void {
        this.createEditIdpOpened = true;
    }

    close(): void {
        this.createEditIdpOpened = false;
    }

    reset(): void {
        this.testOngoing = false;
        this.onGoing = false;

        if (
            this.targetForm &&
            this.targetForm.controls &&
            this.targetForm.controls.targetName
        ) {
            this.targetForm.controls.targetName.reset();
        }

        this.target = this.initIdp();
        this.initVal = this.initIdp();
        this.formValues = null;
        this.idpId = '';
        this.inlineAlert.close();
    }

    openCreateEditTarget(editable: boolean, targetId?: number | string) {
        this.editable = editable;
        this.reset();

        if (targetId) {
            this.idpId = targetId;
            this.translateService
                .get('FEDERATED_IDPS.TITLE_EDIT')
                .subscribe(res => (this.modalTitle = res));
            this.idpService.GetFederatedIdp({ id: Number(targetId) }).subscribe(
                target => {
                    this.target = target;
                    this.initVal = clone(target);
                    this.idpService.ListClaimRules({ id: target.id }).subscribe(
                        claimRules => {
                            const claims = claimRules.map(claimRule => {
                                return {
                                    path: claimRule.claim_path,
                                    value: claimRule.value,
                                };
                            });
                            this.claims = claims;
                            this.initClaims = clone(claims);
                        },
                        error => this.errorHandler.error(error)
                    );
                    this.open();
                    // this.editDisabled = true;
                },
                error => this.errorHandler.error(error)
            );
        } else {
            // this.urlDisabled = false;
            this.idpId = '';
            this.translateService
                .get('FEDERATED_IDPS.TITLE_ADD')
                .subscribe(res => (this.modalTitle = res));
            this.open();
            // this.editDisabled = false;
        }
    }

    onSubmit() {
        if (this.idpId) {
            this.updateIdp();
        } else {
            console.log('🚀 Create IDP');
            this.addIdp();
        }
    }

    addIdp() {
        if (this.onGoing) return;

        this.onGoing = true;
        this.okButtonState = ClrLoadingState.LOADING;
        console.log('this.target:', this.target);

        this.target.jwks_keys = JSON.parse(this.jwksKeys);

        if (!this.validateRequiredClaims(this.claims)) {
            return;
        }

        this.idpService.CreateFederatedIdp({ idp: this.target }).subscribe(
            response => {
                console.log('create fed idp response:', response);
                // this.idpService.CreateClaimRules({ id: response.id }).subscribe(
                this.translateService
                    .get('FEDERATED_IDPS.CREATED_SUCCESS')
                    .subscribe(res => this.errorHandler.info(res));
                console.log('this.claims:', this.claims);
                // assemble claim rules
                const assembledClaimRules = this.assembleClaimRules(
                    this.claims,
                    response.id
                );
                console.log('assembleClaimRules:', assembledClaimRules);

                if (this.claims.length > 0) {
                    this.idpService
                        .CreateClaimRules({
                            id: response.id,
                            claims: { rules: assembledClaimRules },
                        })
                        .subscribe(
                            response => {
                                console.log(
                                    'create claim rules response:',
                                    response
                                );
                                this.reload.emit(true);
                                this.onGoing = false;
                                this.okButtonState = ClrLoadingState.SUCCESS;
                                this.close();
                            },
                            error => {
                                console.log('create claim rules error:', error);
                                this.onGoing = false;
                                this.okButtonState = ClrLoadingState.ERROR;
                                this.inlineAlert.showInlineError(error);
                            }
                        );
                }
                this.reload.emit(true);
                this.onGoing = false;
                this.okButtonState = ClrLoadingState.SUCCESS;
                this.close();
            },
            error => {
                this.onGoing = false;
                this.okButtonState = ClrLoadingState.ERROR;
                this.inlineAlert.showInlineError(error);
            }
        );
    }

    updateIdp() {
        if (this.onGoing || !this.target.id) return;
        if (!this.validateRequiredClaims(this.claims)) {
            return;
        }

        const changes = this.getChanges();
        const claimsChanges = this.getClaimsChanges();
        if (isEmptyObject(changes) && isEmptyObject(claimsChanges)) return;
        // get the changes and update the idp
        // Prepare the updated IDP object
        const updatedIdp = {
            ...this.target,
            ...changes,
        };

        const claimAddPayload = this.assembleClaimsToAddRules(
            claimsChanges.claimsToAdd,
            this.target.id
        );
        const claimDeletePayload = this.assembleClaimsToDeleteRules(
            claimsChanges.claimsToDelete,
            this.target.id
        );

        console.log('this.target:', this.target);
        console.log('this.changes:', changes);
        console.log('updatedIdp:', updatedIdp);

        this.onGoing = true;
        this.okButtonState = ClrLoadingState.LOADING;

        this.idpService
            .UpdateFederatedIdp({ idp: updatedIdp, id: this.target.id })
            .subscribe(
                () => {
                    this.translateService
                        .get('FEDERATED_IDPS.UPDATED_SUCCESS')
                        .subscribe(res => this.errorHandler.info(res));
                    const assembledClaimRules = this.assembleClaimRules(
                        this.claims,
                        this.target.id
                    );
                    console.log('assembleClaimRules:', assembledClaimRules);

                    if (claimDeletePayload.length > 0) {
                        this.idpService
                            .DeleteClaimRules({
                                id: this.target.id,
                                claims: { rules: claimDeletePayload },
                            })
                            .subscribe(
                                response => {
                                    console.log(
                                        'create claim rules response:',
                                        response
                                    );
                                },
                                error => {
                                    console.log(
                                        'create claim rules error:',
                                        error
                                    );
                                    this.onGoing = false;
                                    this.okButtonState = ClrLoadingState.ERROR;
                                    this.inlineAlert.showInlineError(error);
                                }
                            );
                    }

                    if (claimAddPayload.length > 0) {
                        this.idpService
                            .CreateClaimRules({
                                id: this.target.id,
                                claims: { rules: claimAddPayload },
                            })
                            .subscribe(
                                response => {
                                    console.log(
                                        'create claim rules response:',
                                        response
                                    );
                                },
                                error => {
                                    console.log(
                                        'create claim rules error:',
                                        error
                                    );
                                    this.onGoing = false;
                                    this.okButtonState = ClrLoadingState.ERROR;
                                    this.inlineAlert.showInlineError(error);
                                }
                            );
                    }
                },
                error => {
                    this.inlineAlert.showInlineError(error);
                    this.onGoing = false;
                    this.okButtonState = ClrLoadingState.ERROR;
                }
            );
        this.reload.emit(true);
        this.close();
        this.onGoing = false;
        this.okButtonState = ClrLoadingState.SUCCESS;
    }

    onCancel() {
        const changes = this.getChanges();
        const claimsChanges = this.getClaimsChanges();
        if (!isEmptyObject(changes) || !isEmptyObject(claimsChanges)) {
            this.inlineAlert.showInlineConfirmation({
                message: 'ALERT.FORM_CHANGE_CONFIRMATION',
            });
        } else {
            this.close();
            if (this.targetForm) {
                this.targetForm.reset();
            }
        }
    }

    validateRequiredClaims(claims: { path: string; value: string }[]): boolean {
        // 🛑 Check if claims is valid array
        if (!claims || !Array.isArray(claims)) {
            console.error('Invalid claims array provided.');
            return false;
        }

        // 🔍 Extract all claim paths
        const paths = claims.map(c => c.path.toLowerCase());

        // ✅ Required claim keys
        const requiredKeys = ['aud', 'iss'];

        // 🔎 Find missing ones
        const missing = requiredKeys.filter(key => !paths.includes(key));

        if (missing.length > 0) {
            console.error(
                `Missing required claim path(s): ${missing.join(', ')}`
            );
            this.inlineAlert.showInlineError(
                `Missing required claim path(s): ${missing.join(', ')}`
            );
            // 🔁 You can also show an inline UI error here if you prefer
            // this.inlineAlert.showInlineError(`Missing required claim(s): ${missing.join(", ")}`);
            return false;
        }

        // ✅ Everything present
        return true;
    }

    assembleClaimsToAddRules(
        claimsToAdd: { path: string; value: string }[],
        id: number
    ) {
        if (!claimsToAdd || !Array.isArray(claimsToAdd)) {
            console.error("Input 'claimsToAdd' is not a valid array.");
            return [];
        }
        if (id === 0 || id === undefined) {
            console.error("Input is missing an 'id' property.");
            return [];
        }

        // 🆕 Builds rules for new claims to insert
        return claimsToAdd.map(claim => ({
            claim_path: claim.path,
            value: claim.value,
            identity_provider_id: id,
            action: 'add', // 👈 Added field to explicitly identify the operation
        }));
    }

    assembleClaimsToDeleteRules(
        claimsToDelete: { path: string; value: string }[],
        id: number
    ) {
        if (!claimsToDelete || !Array.isArray(claimsToDelete)) {
            console.error("Input 'claimsToDelete' is not a valid array.");
            return [];
        }
        if (id === 0 || id === undefined) {
            console.error("Input is missing an 'id' property.");
            return [];
        }

        // 🗑 Builds rules for claims to remove
        return claimsToDelete.map(claim => ({
            claim_path: claim.path,
            value: claim.value,
            identity_provider_id: id,
            action: 'delete', // 👈 Added for clarity in downstream processing
        }));
    }

    assembleClaimRules(claims: { path: string; value: string }[], id: number) {
        if (!claims || !Array.isArray(claims)) {
            console.error("Input 'claims' is not a valid array.");
            return [];
        }
        if (id === 0 || id === undefined) {
            console.error("Input is missing an 'id' property.");
            return [];
        }

        return claims.map(claim => {
            return {
                claim_path: claim.path,
                value: claim.value,
                identity_provider_id: id,
            };
        });
    }

    confirmCancel(confirmed: boolean) {
        this.inlineAlert.close();
        this.close();
    }

    ngAfterViewChecked(): void {
        if (this.targetForm !== this.currentForm) {
            this.targetForm = this.currentForm;
            if (this.targetForm) {
                this.valueChangesSub = this.targetForm.valueChanges.subscribe(
                    (data: any) => {
                        if (!compareValue(this.formValues, data)) {
                            this.formValues = data;
                        }
                    }
                );
            }
        }
    }

    getClaimsChanges(): {
        claimsToAdd: { path: string; value: string }[];
        claimsToDelete: { path: string; value: string }[];
    } {
        const claimsToAdd: { path: string; value: string }[] = [];
        const claimsToDelete: { path: string; value: string }[] = [];
        // ✅ Return early if either array is empty
        if (!this.claims?.length || !this.initClaims?.length) {
            return { claimsToAdd, claimsToDelete }; // both empty
        }

        // ✅ Convert both arrays into Map for O(1) lookup by `path`
        const currentMap = new Map(this.claims.map(c => [c.path, c.value]));
        const initMap = new Map(this.initClaims.map(c => [c.path, c.value]));

        // ✅ Iterate over initial claims to detect deletions or modifications
        for (const [path, oldValue] of initMap.entries()) {
            const newValue = currentMap.get(path);

            if (newValue === undefined) {
                // 🗑 Claim removed → delete
                claimsToDelete.push({ path, value: oldValue });
            } else if (!compareValue(oldValue, newValue)) {
                // ✏️ Modified → delete old + add new
                claimsToDelete.push({ path, value: oldValue });
                claimsToAdd.push({ path, value: newValue });
            }
        }

        // ✅ Detect newly added claims
        for (const [path, newValue] of currentMap.entries()) {
            if (!initMap.has(path)) {
                // ➕ New claim added
                claimsToAdd.push({ path, value: newValue });
            }
        }

        return { claimsToAdd, claimsToDelete };
    }

    getChanges(): { [key: string]: any | any[] } {
        const changes: { [key: string]: any | any[] } = {};
        if (!this.target || !this.initVal) return changes;

        for (const prop of Object.keys({ ...this.target, ...this.initVal })) {
            const original = this.initVal[prop];
            const current = this.target[prop];

            if (typeof original !== 'object') {
                if (!compareValue(original, current)) {
                    changes[prop] =
                        typeof original === 'string'
                            ? ('' + current).trim()
                            : current;
                }
            } else {
                for (const subProp of Object.keys({
                    ...original,
                    ...current,
                })) {
                    if (
                        !compareValue(original?.[subProp], current?.[subProp])
                    ) {
                        changes[subProp] =
                            typeof original[subProp] === 'string'
                                ? ('' + current[subProp]).trim()
                                : current[subProp];
                    }
                }
            }
        }

        return changes;
    }
}

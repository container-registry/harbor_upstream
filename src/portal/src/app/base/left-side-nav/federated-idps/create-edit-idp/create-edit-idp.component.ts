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
import { FederatedIdpService } from 'src/app/shared/services';

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
    openIDConfigJSON: string;
    jwksKeys: string;
    initVal: FederatedIdp;
    targetForm: NgForm;
    @ViewChild('targetForm') currentForm: NgForm;
    testOngoing: boolean;
    onGoing: boolean;
    idpId: number | string;

    // Array to store claim data
    claims: { path: string; value: string }[] = [{ path: '', value: '' }];

    @ViewChild(InlineAlertComponent) inlineAlert: InlineAlertComponent;

    @Output() reload = new EventEmitter<boolean>();

    valueChangesSub: Subscription;
    formValues: { [key: string]: string } | any;
    adapterInfo: object;
    showEndpointList: boolean = false;
    endpointOnHover: boolean = false;
    testButtonState: ClrLoadingState = ClrLoadingState.DEFAULT;
    okButtonState: ClrLoadingState = ClrLoadingState.DEFAULT;

    constructor(
        private idpService: FederatedIdpService,
        private errorHandler: ErrorHandler,
        private translateService: TranslateService,
        private http: HttpClient,
        private appConfigService: AppConfigService
    ) {}

    ngOnInit(): void {
        return;
        // this.getAdapters();
        // this.getAdapterInfo();
    }

    selectedEndpoint(endpoint: string) {
        this.targetForm.controls.endpointUrl.reset(endpoint);
        this.showEndpointList = false;
        this.endpointOnHover = false;
    }

    blur() {
        if (!this.endpointOnHover) {
            this.showEndpointList = false;
        }
    }

    public get isValid(): boolean {
        return (
            !this.testOngoing &&
            !this.onGoing &&
            this.targetForm &&
            this.targetForm.valid &&
            this.editable &&
            !compareValue(this.target, this.initVal)
        );
    }

    public get inProgress(): boolean {
        return this.onGoing || this.testOngoing;
    }

    setOfflineValidation($event: any) {
        this.target.offline_validation = !$event;
    }

    // Function to add a new claim pair
    addClaim(): void {
        this.claims.push({ path: '', value: '' });
    }

    removeClaim(): void {
        // Remove the last claim from the claims Array
        if (this.claims.length === 1) {
            return;
        }
        // this.claims.pop();
        // get the length of the claims Array
        const length = this.claims.length;
        // remove the claim at the specified index
        this.claims.splice(length - 1, 1);
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
            creation_time: '',
            update_time: '',
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
            this.idpService.getFederatedIdp(targetId).subscribe(
                target => {
                    this.target = target;
                    // this.urlDisabled =
                    //     this.adapterInfo &&
                    //     this.adapterInfo[this.target.type] &&
                    //     this.adapterInfo[this.target.type].endpoint_pattern &&
                    //     this.adapterInfo[this.target.type].endpoint_pattern
                    //         .endpoint_type === FIXED_PATTERN_TYPE;
                    this.initVal = clone(target);
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
            this.addIdp();
        }
    }

    addIdp() {
        if (this.onGoing) return;

        this.onGoing = true;
        this.okButtonState = ClrLoadingState.LOADING;

        this.idpService.createFederatedIdp(this.target).subscribe(
            () => {
                this.translateService
                    .get('FEDERATED_IDPS.CREATED_SUCCESS')
                    .subscribe(res => this.errorHandler.info(res));
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

        const changes = this.getChanges();
        if (isEmptyObject(changes)) return;

        this.onGoing = true;
        this.okButtonState = ClrLoadingState.LOADING;

        this.idpService.updateFederatedIdp(this.target.id, changes).subscribe(
            () => {
                this.translateService
                    .get('FEDERATED_IDPS.UPDATED_SUCCESS')
                    .subscribe(res => this.errorHandler.info(res));
                this.reload.emit(true);
                this.close();
                this.onGoing = false;
                this.okButtonState = ClrLoadingState.SUCCESS;
            },
            error => {
                this.inlineAlert.showInlineError(error);
                this.onGoing = false;
                this.okButtonState = ClrLoadingState.ERROR;
            }
        );
    }

    onCancel() {
        const changes = this.getChanges();
        if (!isEmptyObject(changes)) {
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

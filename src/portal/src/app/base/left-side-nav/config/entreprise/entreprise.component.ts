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
import { Component, OnInit, ViewChild } from '@angular/core';
import { NgForm } from '@angular/forms';
import { MessageHandlerService } from '../../../../shared/services/message-handler.service';
import { AppConfigService } from '../../../../services/app-config.service';
import { ConfigurationService } from '../../../../services/config.service';
import { SystemInfoService } from '../../../../shared/services';
import {
    getChanges as getChangesFunc,
    isEmpty,
} from '../../../../shared/units/utils';
import { CONFIG_AUTH_MODE } from '../../../../shared/entities/shared.const';
import { Configuration } from '../config';
import { ConfigService } from '../config.service';

@Component({
    selector: 'entreprise',
    templateUrl: './entreprise.component.html',
    styleUrls: ['./entreprise.component.scss'],
})
export class EntrepriseComponent implements OnInit {
    testingOnGoing = false;
    onGoing = false;
    redirectUrl: string;
    @ViewChild('entrepriseConfigFrom') entrepriseForm: NgForm;

    get currentConfig(): Configuration {
        return this.conf.getConfig();
    }

    set currentConfig(c: Configuration) {
        this.conf.setConfig(c);
    }

    constructor(
        private msgHandler: MessageHandlerService,
        private configService: ConfigurationService,
        private appConfigService: AppConfigService,
        private conf: ConfigService,
        private systemInfo: SystemInfoService
    ) {}
    ngOnInit() {
        this.conf.resetConfig();
        this.getSystemInfo();
    }
    getSystemInfo(): void {
        this.systemInfo.getSystemInfo().subscribe(
            systemInfo => (this.redirectUrl = systemInfo.external_url),
            error => this.msgHandler.error(error)
        );
    }
    get checkable() {
        return (
            this.currentConfig &&
            this.currentConfig.self_registration &&
            this.currentConfig.self_registration.value === true
        );
    }

    isValid(): boolean {
        return this.entrepriseForm && this.entrepriseForm.valid;
    }

    inProcess(): boolean {
        return this.onGoing || this.conf.getLoadingConfigStatus();
    }

    hasChanges(): boolean {
        return !isEmpty(this.getChanges());
    }

    public getChanges() {
        let allChanges = getChangesFunc(
            this.conf.getOriginalConfig(),
            this.currentConfig
        );
        let changes = {};
        for (let prop in allChanges) {
            if (
                prop.startsWith('ldap_') ||
                prop.startsWith('uaa_') ||
                prop.startsWith('oidc_') ||
                prop === 'auth_mode' ||
                prop === 'project_creattion_restriction' ||
                prop === 'enable_project_federated_idp' ||
                prop === 'projectFedIdp' ||
                prop.startsWith('http_')
            ) {
                changes[prop] = allChanges[prop];
            }
        }
        return changes;
    }

    disabled(prop: any): boolean {
        return !(prop && prop.editable);
    }

    handleOnChange($event: any): void {
        if ($event && $event.target && $event.target['value']) {
            let authMode = $event.target['value'];
            if (
                authMode === CONFIG_AUTH_MODE.LDAP_AUTH ||
                authMode === CONFIG_AUTH_MODE.UAA_AUTH ||
                authMode === CONFIG_AUTH_MODE.HTTP_AUTH ||
                authMode === CONFIG_AUTH_MODE.OIDC_AUTH
            ) {
                if (this.currentConfig.self_registration.value) {
                    this.currentConfig.self_registration.value = false; // unselect
                }
            }
        }
    }

    /**
     *
     * Save the changed values
     *
     * @memberOf ConfigurationComponent
     */
    public save(): void {
        let changes = this.getChanges();
        if (!isEmpty(changes)) {
            this.onGoing = true;
            this.configService.saveConfiguration(changes).subscribe(
                response => {
                    this.onGoing = false;
                    this.conf.updateConfig();
                    // Reload bootstrap option
                    this.appConfigService.load().subscribe(
                        () => {},
                        error =>
                            console.error(
                                'Failed to reload bootstrap option with error: ',
                                error
                            )
                    );
                    this.msgHandler.showSuccess('CONFIG.SAVE_SUCCESS');
                },
                error => {
                    this.onGoing = false;
                    this.msgHandler.handleError(error);
                }
            );
        } else {
            // Inprop situation, should not come here
            console.error('Save abort because nothing changed');
        }
    }

    /**
     *
     * Discard current changes if have and reset
     *
     * @memberOf ConfigurationComponent
     */
    public cancel(): void {
        let changes = this.getChanges();
        if (!isEmpty(changes)) {
            this.conf.confirmUnsavedChanges(changes);
        } else {
            // Invalid situation, should not come here
            console.error('Nothing changed');
        }
    }
}

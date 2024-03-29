﻿// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using System.Linq;

using Keyfactor.Platform.Extensions.Agents;
using Keyfactor.Platform.Extensions.Agents.Enums;
using Keyfactor.Platform.Extensions.Agents.Delegates;
using Keyfactor.Platform.Extensions.Agents.Interfaces;

using CSS.Common.Logging;

using Newtonsoft.Json;

using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.PKCS12
{
    public class Management : LoggingClientBase, IAgentJobExtension
    {
        public string GetJobClass()
        {
            return "Management";
        }

        public string GetStoreType()
        {
            return "PKCS12";
        }

        public AnyJobCompleteInfo processJob(AnyJobConfigInfo config, SubmitInventoryUpdate submitInventory, SubmitEnrollmentRequest submitEnrollmentRequest, SubmitDiscoveryResults sdr)
        {
            Logger.Debug($"Begin PKCS12 Management-{Enum.GetName(typeof(AnyJobOperationType), config.Job.OperationType)} job for job id {config.Job.JobId}...");

            PKCS12Store pkcs12Store = new PKCS12Store(config.Store.ClientMachine, config.Server.Username, config.Server.Password, config.Store.StorePath, config.Store.StorePassword);

            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                bool hasPassword = !string.IsNullOrEmpty(config.Job.PfxPassword);
                pkcs12Store.Initialize();

                switch (config.Job.OperationType)
                {
                    case AnyJobOperationType.Add:
                        Logger.Debug($"Begin Create Operation for {config.Store.StorePath} on {config.Store.ClientMachine}.");
                        if (!pkcs12Store.DoesStoreExist())
                        {
                            throw new PKCS12Exception($"Certificate store {pkcs12Store.StorePath + pkcs12Store.StoreFileName} does not exist on server {pkcs12Store.Server}.");
                        }
                        else
                        {
                            pkcs12Store.AddCertificate(config.Job.Alias, config.Job.EntryContents, config.Job.Overwrite, config.Job.PfxPassword);
                        }
                        break;

                    case AnyJobOperationType.Remove:
                        Logger.Debug($"Begin Delete Operation for {config.Store.StorePath} on {config.Store.ClientMachine}.");
                        if (!pkcs12Store.DoesStoreExist())
                        {
                            throw new PKCS12Exception($"Certificate store {pkcs12Store.StorePath + pkcs12Store.StoreFileName} does not exist on server {pkcs12Store.Server}.");
                        }
                        else
                        {
                            pkcs12Store.DeleteCertificateByAlias(config.Job.Alias);
                        }
                        break;

                    case AnyJobOperationType.Create:
                        Logger.Debug($"Begin Create Operation for {config.Store.StorePath} on {config.Store.ClientMachine}.");
                        if (pkcs12Store.DoesStoreExist())
                        {
                            throw new PKCS12Exception($"Certificate store {pkcs12Store.StorePath + pkcs12Store.StoreFileName} already exists.");
                        }
                        else
                        {
                            dynamic properties = JsonConvert.DeserializeObject(config.Store.Properties.ToString());
                            string linuxFilePermissions = properties.linuxFilePermissionsOnStoreCreation == null || string.IsNullOrEmpty(properties.linuxFilePermissionsOnStoreCreation.Value) ?
                                ApplicationSettings.DefaultLinuxPermissionsOnStoreCreation :
                                properties.linuxFilePermissionsOnStoreCreation.Value;

                            pkcs12Store.CreateCertificateStore(config.Store.StorePath, linuxFilePermissions);
                        }
                        break;

                    default:
                        return new AnyJobCompleteInfo() { Status = 4, Message = $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}: Unsupported operation: {config.Job.OperationType.ToString()}" };
                }
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }
            finally
            {
                pkcs12Store.Terminate();
            }

            return new AnyJobCompleteInfo() { Status = 2, Message = "Successful" };
        }
    }
}
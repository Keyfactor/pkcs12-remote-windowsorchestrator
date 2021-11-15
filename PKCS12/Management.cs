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
            return "JKS-SSH";
        }

        public AnyJobCompleteInfo processJob(AnyJobConfigInfo config, SubmitInventoryUpdate submitInventory, SubmitEnrollmentRequest submitEnrollmentRequest, SubmitDiscoveryResults sdr)
        {
            Logger.Debug($"Begin PKCS12 Management-{Enum.GetName(typeof(AnyJobOperationType), config.Job.OperationType)} job for job id {config.Job.JobId}...");

            PKCS12Store PKCS12Store = new PKCS12Store(config.Store.ClientMachine, config.Server.Username, config.Server.Password, config.Store.StorePath, config.Store.StorePassword);

            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                bool hasPassword = !string.IsNullOrEmpty(config.Job.PfxPassword);
                PKCS12Store.Initialize();

                switch (config.Job.OperationType)
                {
                    case AnyJobOperationType.Add:
                        byte[] certBytes = Convert.FromBase64String(config.Job.EntryContents);
                        MemoryStream stream = new MemoryStream(certBytes);
                        Pkcs12Store store;
                        string sourceAlias;

                        if (hasPassword)
                        {
                            store = new Pkcs12Store(stream, config.Job.PfxPassword.ToCharArray());
                            sourceAlias = store.Aliases.Cast<string>().FirstOrDefault(p => store.IsKeyEntry(p));
                            PKCS12Store.AddPFXCertificateToStore(sourceAlias, config.Job.Alias, certBytes, config.Job.PfxPassword, entryPassword, config.Job.Overwrite);
                        }
                        else
                            PKCS12Store.AddCertificateToStore(config.Job.Alias, certBytes, config.Job.Overwrite);

                        break;

                    case AnyJobOperationType.Remove:
                        PKCS12Store.DeleteCertificateByAlias(config.Job.Alias);

                        break;

                    case AnyJobOperationType.Create:
                        Logger.Debug($"Begin Create Operation for {config.Store.StorePath} on {config.Store.ClientMachine}.");
                        PKCS12Store.CreateCertificateStore(config.Store.StorePath, config.Store.StorePassword);
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
                PKCS12Store.Terminate();
            }

            return new AnyJobCompleteInfo() { Status = 2, Message = "Successful" };
        }
    }
}
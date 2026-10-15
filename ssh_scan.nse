description = [[
NetSentinel SSH Algorithm Scanner

Connects to an SSH server, performs the SSH handshake,
collects the algorithms advertised during key exchange,
and displays the supported cryptographic algorithms.
]]

author = "Sunesh Krishna"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "version"}

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ssh2 = require "ssh2"

portrule = shortport.ssh

----------------------------------------------------------
-- Algorithm Classification Rules
----------------------------------------------------------

local MODERN_RULES = {
    "curve25519",
    "mlkem",
    "ecdh",
    "chacha20",
    "gcm",
    "ctr",
    "ssh-ed25519",
    "ecdsa",
    "sha2",
    "umac"
}

local LEGACY_RULES = {
    "group1",
    "3des",
    "arcfour",
    "ssh-dss",
    "md5"
}

----------------------------------------------------------
-- Helper Functions
----------------------------------------------------------

local function contains_algorithm(list, pattern)

    if not list then
        return false
    end

    for alg in string.gmatch(list, "([^,]+)") do

        if alg:find(pattern, 1, true) then
            return true
        end

    end

    return false

end

local function split_algorithms(list)

    local algorithms = {}

    if not list then
        return algorithms
    end

    for alg in string.gmatch(list, "([^,]+)") do
        table.insert(algorithms, alg)
    end

    return algorithms

end
----------------------------------------------------------
-- Collect SSH Algorithms
----------------------------------------------------------

local function collect_algorithms(host, port)

    local socket = nmap.new_socket()

    local status = socket:connect(host, port)

    if not status then
        return false, "Failed to connect to SSH server."
    end

    status = socket:send("SSH-2.0-NetSentinel\r\n")

    if not status then
        socket:close()
        return false, "Failed to send SSH banner."
    end

    status = socket:receive_buf("\r?\n", false)

    if not status then
        socket:close()
        return false, "Failed to receive SSH banner."
    end

    local ssh = ssh2.transport

    status = socket:send(
        ssh.build(
            ssh.kex_init()
        )
    )

    if not status then
        socket:close()
        return false, "Failed to send SSH KEXINIT packet."
    end

    local response

    status, response = ssh.receive_packet(socket)

    socket:close()

    if not status then
        return false, "Failed to receive SSH KEXINIT response."
    end

    local parsed = ssh.parse_kex_init(
        ssh.payload(response)
    )

    return true, parsed

end
----------------------------------------------------------
-- Analyze Algorithms
----------------------------------------------------------

local function analyze_algorithms(parsed)

    local result = {}

    result.kex = split_algorithms(parsed.kex_algorithms)
    result.host_keys = split_algorithms(parsed.server_host_key_algorithms)
    result.encryption = split_algorithms(parsed.encryption_algorithms_server_to_client)
    result.mac = split_algorithms(parsed.mac_algorithms_server_to_client)
    result.compression = split_algorithms(parsed.compression_algorithms_server_to_client)

    result.modern = {}
    result.legacy = {}

    local checked = {}

    local function classify(list)

        for _, algorithm in ipairs(list) do

            if not checked[algorithm] then

                checked[algorithm] = true

                for _, pattern in ipairs(MODERN_RULES) do

                    if algorithm:find(pattern, 1, true) then
                        table.insert(result.modern, algorithm)
                        goto continue
                    end

                end

                for _, pattern in ipairs(LEGACY_RULES) do

                    if algorithm:find(pattern, 1, true) then
                        table.insert(result.legacy, algorithm)
                        goto continue
                    end

                end

            end

            ::continue::

        end

    end

    classify(result.kex)
    classify(result.host_keys)
    classify(result.encryption)
    classify(result.mac)
    classify(result.compression)

    return result

end
----------------------------------------------------------
-- Report Generator
----------------------------------------------------------

local function add_section(report, title, list)

    table.insert(report, title)
    table.insert(report, string.rep("-", #title))

    if not list or #list == 0 then
        table.insert(report, "None")
    else
        for _, value in ipairs(list) do
            table.insert(report, value)
        end
    end

    table.insert(report, "")

end


local function generate_report(host, port, result)

    local report = {}

    table.insert(report,"=========================================================")
    table.insert(report," NetSentinel SSH Algorithm Scanner")
    table.insert(report,"=========================================================")
    table.insert(report,"")

    table.insert(report,"Target Information")
    table.insert(report,"------------------")
    table.insert(report,"Host : " .. host.ip)
    table.insert(report,"Port : " .. port.number)
    table.insert(report,"")

    add_section(report,"Key Exchange Algorithms",result.kex)
    add_section(report,"Host Key Algorithms",result.host_keys)
    add_section(report,"Encryption Algorithms",result.encryption)
    add_section(report,"MAC Algorithms",result.mac)
    add_section(report,"Compression Algorithms",result.compression)

    table.insert(report,"Algorithm Classification")
    table.insert(report,"------------------------")
    table.insert(report,"")

    add_section(report,"Modern Algorithms",result.modern)
    add_section(report,"Legacy Algorithms",result.legacy)

    table.insert(report,"=========================================================")

    return stdnse.format_output(true, report)

end
----------------------------------------------------------
-- Action
----------------------------------------------------------

action = function(host, port)

    local status, parsed = collect_algorithms(host, port)

    if not status then
        return parsed
    end

    local result = analyze_algorithms(parsed)

    return generate_report(host, port, result)

end

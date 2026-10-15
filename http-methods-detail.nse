
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends one HTTP OPTIONS request and reports the response status,
advertised methods, and selected protocol headers.

This script does not probe individual HTTP methods or attempt
to determine whether unadvertised methods are implemented.
]]

author = "Custom NSE script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local MAX_PATH_LENGTH = 2048

local function clean(value)
  if value == nil then
    return nil
  end

  local result = tostring(value):gsub("[\r\n]+", " ")
  return result
end

local function validate_path(path)
  if path == nil or path == "" then
    return "/"
  end

  if path:find("[%c]") then
    error("Path contains control characters")
  end

  if path:find("#", 1, true) then
    error("Path must not contain a URL fragment")
  end

  if path:find("%s") then
    error("Path contains whitespace; percent-encode spaces")
  end

  if path:find("\\", 1, true) then
    error("Path must not contain backslashes")
  end

  if path:match("^[%a][%w+%.%-]*://")
      or path:sub(1, 2) == "//" then
    error("Specify an origin path, not a complete URL")
  end

  if path:sub(1, 1) ~= "/" then
    path = "/" .. path
  end

  if #path > MAX_PATH_LENGTH then
    error("Path exceeds the 2048-character limit")
  end

  return path
end

local function add_header(lines, headers, name, label)
  if not headers then
    return
  end

  local value = headers[name:lower()]

  if value ~= nil and tostring(value) ~= "" then
    lines[#lines + 1] = label .. ": " .. clean(value)
  end
end

action = function(host, port)
  local argument = stdnse.get_script_args(
    "http-methods-detail.path"
  )

  local path_ok, path = pcall(validate_path, argument)

  if not path_ok then
    return "Invalid path: " .. clean(path)
  end

  local request_ok, response = pcall(function()
    return http.generic_request(host, port, "OPTIONS", path, {
      timeout = 10000,
      redirect_ok = false
    })
  end)

  if not request_ok then
    return "OPTIONS request failed: " .. clean(response)
  end

  if type(response) ~= "table" then
    return "OPTIONS request failed: no HTTP response object"
  end

  if not response.status then
    return "OPTIONS request failed: " .. clean(
      response["status-line"] or "No HTTP status received"
    )
  end

  local headers = response.header or {}

  local lines = {
    "Request: OPTIONS " .. path,
    "Status: " .. clean(
      response["status-line"] or response.status
    ),
    "Note: only OPTIONS was requested; other methods were not tested"
  }

  if response.version then
    lines[#lines + 1] =
      "HTTP version: " .. clean(response.version)
  end

  add_header(lines, headers, "allow", "Allow")
  add_header(lines, headers, "public", "Public")
  add_header(lines, headers, "dav", "DAV")
  add_header(lines, headers, "accept-patch", "Accept-Patch")
  add_header(lines, headers, "accept-post", "Accept-Post")
  add_header(lines, headers, "content-type", "Content-Type")
  add_header(lines, headers, "content-length", "Content-Length")
  add_header(lines, headers, "location", "Location")
  add_header(lines, headers, "server", "Server")

  if not headers.allow and not headers.public then
    lines[#lines + 1] =
      "Advertised methods: no Allow/Public header returned"
  else
    local method_headers = {}

    if headers.allow and headers.allow ~= "" then
      method_headers[#method_headers + 1] =
        "Allow=" .. clean(headers.allow)
    end

    if headers.public and headers.public ~= "" then
      method_headers[#method_headers + 1] =
        "Public=" .. clean(headers.public)
    end

    if #method_headers > 0 then
      lines[#lines + 1] =
        "Method information: " .. table.concat(method_headers, "; ")
    end
  end

  return table.concat(lines, "\n")
end

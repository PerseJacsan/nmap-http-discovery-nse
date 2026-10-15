
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Requests a small, user-controlled list of HTTP paths and reports
response status, content type, content length, server identity,
and redirect information.

Uses HEAD first and falls back to a bounded GET when HEAD returns
405 or 501. Follows only origin-relative absolute-path redirects,
with a maximum of three redirects per requested path.
]]

author = "Custom NSE script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local MAX_PATHS = 20
local MAX_PATH_LENGTH = 2048
local MAX_REDIRECTS = 3
local MAX_GET_BODY_SIZE = 1024

local DEFAULT_PATHS = {
  "/",
  "/robots.txt",
  "/sitemap.xml",
  "/favicon.ico"
}

local function clean(value)
  if value == nil then
    return nil
  end

  local result = tostring(value):gsub("[\r\n]+", " ")
  return result
end

local function validate_path(path)
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

local function parse_paths(value)
  if not value or value == "" then
    return DEFAULT_PATHS
  end

  local paths = {}

  -- Pipe separates paths in the script argument.
  for item in value:gmatch("[^|]+") do
    local path = item:match("^%s*(.-)%s*$")

    if path ~= "" then
      local ok, validated = pcall(validate_path, path)

      if not ok then
        error("Invalid path '" .. path .. "': " .. tostring(validated))
      end

      paths[#paths + 1] = validated

      if #paths > MAX_PATHS then
        error("At most 20 paths may be supplied")
      end
    end
  end

  if #paths == 0 then
    error("No valid paths supplied")
  end

  return paths
end

local function request_once(host, port, method, path)
  local options = {
    timeout = 10000,
    redirect_ok = false
  }

  if method == "GET" then
    options.max_body_size = MAX_GET_BODY_SIZE
    options.truncated_ok = true
  end

  local ok, response = pcall(function()
    return http.generic_request(
      host,
      port,
      method,
      path,
      options
    )
  end)

  if not ok then
    return nil, clean(response)
  end

  if type(response) ~= "table" then
    return nil, "No HTTP response object"
  end

  if not response.status then
    return nil, clean(
      response["status-line"] or "No HTTP status received"
    )
  end

  return response
end

local function request_path(host, port, path)
  local head, head_error = request_once(
    host, port, "HEAD", path
  )

  if not head then
    return nil, "HEAD", head_error
  end

  local head_status = tonumber(head.status)

  if head_status == 405 or head_status == 501 then
    local get_response, get_error = request_once(
      host, port, "GET", path
    )

    local head_line = clean(
      head["status-line"] or head.status
    )

    if get_response then
      local get_line = clean(
        get_response["status-line"] or get_response.status
      )

      local detail = "HEAD returned " .. head_line
        .. "; GET fallback returned " .. get_line

      if get_response.truncated then
        detail = detail .. " (response body truncated)"
      end

      return get_response, "GET", nil, head, detail
    end

    local detail = "HEAD returned " .. head_line
      .. "; GET fallback failed: " .. tostring(get_error)

    return head, "HEAD", nil, head, detail
  end

  return head, "HEAD", nil, head, nil
end

local function is_redirect(status)
  return status == 301
      or status == 302
      or status == 303
      or status == 307
      or status == 308
end

local function safe_redirect_path(location)
  if not location or location == "" then
    return nil
  end

  if location:find("[%c]")
      or location:find("#", 1, true)
      or location:find("%s")
      or location:find("\\", 1, true) then
    return nil
  end

  -- Absolute URLs and scheme-relative URLs are deliberately not
  -- followed. Only an origin-relative absolute path is accepted.
  if location:match("^[%a][%w+%.%-]*://")
      or location:sub(1, 2) == "//" then
    return nil
  end

  if location:sub(1, 1) ~= "/" then
    return nil
  end

  if #location > MAX_PATH_LENGTH then
    return nil
  end

  return location
end

local function inspect_path(host, port, original_path)
  local current_path = original_path
  local visited = {}
  local redirect_chain = {}
  local fallback_details = {}
  local first_response
  local final_response
  local final_method
  local redirect_note

  for hop = 0, MAX_REDIRECTS do
    if visited[current_path] then
      redirect_note = "Redirect loop detected"
      break
    end

    visited[current_path] = true

    local response, method, request_error, head_response, fallback_detail =
      request_path(host, port, current_path)

    if not response then
      return {
        path = original_path,
        error = request_error or "Request failed"
      }
    end

    if not first_response then
      first_response = head_response or response
    end

    if fallback_detail then
      fallback_details[#fallback_details + 1] =
        current_path .. ": " .. fallback_detail
    end

    final_response = response
    final_method = method

    local status = tonumber(response.status)
    local headers = response.header or {}
    local location = headers.location

    if not is_redirect(status) or not location then
      break
    end

    local next_path = safe_redirect_path(location)

    if not next_path then
      redirect_note =
        "Redirect not followed: only origin-relative absolute paths are followed"
      break
    end

    if visited[next_path] then
      redirect_note = "Redirect loop detected"
      break
    end

    if hop == MAX_REDIRECTS then
      redirect_note = "Redirect limit reached"
      break
    end

    redirect_chain[#redirect_chain + 1] =
      current_path .. " -> " .. next_path

    current_path = next_path
  end

  if not final_response then
    return {
      path = original_path,
      error = "No final response received"
    }
  end

  return {
    path = original_path,
    first_response = first_response,
    response = final_response,
    final_path = current_path,
    method = final_method,
    redirects = redirect_chain,
    redirect_note = redirect_note,
    fallback_details = fallback_details
  }
end

local function add_header(lines, headers, name, label)
  local value = headers and headers[name:lower()]

  if value ~= nil and tostring(value) ~= "" then
    lines[#lines + 1] = label .. ": " .. clean(value)
  end
end

action = function(host, port)
  local argument = stdnse.get_script_args(
    "http-path-info.paths"
  )

  local ok, paths = pcall(parse_paths, argument)

  if not ok then
    return "Invalid path list: " .. clean(paths)
  end

  local lines = {
    "Paths requested: " .. #paths
  }

  for _, path in ipairs(paths) do
    local result = inspect_path(host, port, path)

    if result.error then
      lines[#lines + 1] =
        path .. " -> Request failed: " .. clean(result.error)
    else
      local first = result.first_response
      local response = result.response
      local headers = response.header or {}

      local first_status = clean(
        first["status-line"] or first.status
      )

      local final_status = clean(
        response["status-line"] or response.status
      )

      local entry = {
        path .. " -> " .. first_status,
        "Method used: " .. result.method
      }

      if #result.redirects > 0 then
        entry[#entry + 1] =
          "Redirect chain: " .. table.concat(result.redirects, " ; ")
      end

      if #result.redirects > 0
          or #result.fallback_details > 0 then
        entry[#entry + 1] =
          "Final destination: " .. result.final_path

        entry[#entry + 1] =
          "Final response: " .. final_status
      end

      for _, detail in ipairs(result.fallback_details) do
        entry[#entry + 1] = "Fallback: " .. detail
      end

      if result.redirect_note then
        entry[#entry + 1] = result.redirect_note
      end

      add_header(entry, headers, "content-type", "Content-Type")
      add_header(entry, headers, "content-length", "Content-Length")
      add_header(entry, headers, "location", "Location")
      add_header(entry, headers, "server", "Server")

      if response.truncated then
        entry[#entry + 1] =
          "Response body was truncated to the configured limit"
      end

      lines[#lines + 1] = table.concat(entry, " | ")
    end
  end

  return table.concat(lines, "\n")
end

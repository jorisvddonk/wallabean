-- wallabean.lua: Implementation of wallabag-compatible API using redbean

sqlite3 = require 'lsqlite3'
argon2 = require 'argon2'

-- Increase max payload size to 10MB to handle large entries
ProgramMaxPayloadSize(10485760)

-- Logging configuration
local log_levels = {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    FATAL = 4
}

local current_log_level = log_levels.INFO -- Default to INFO



-- Helper functions
function get_current_time()
    return os.date('%Y-%m-%dT%H:%M:%S+0000')
end

function json_response(data, status)
    status = status or 200
    local json = EncodeJson(data)
    json = json:gsub('"tags":{}', '"tags":[]')
    log_message(log_levels.INFO, 'Response: ' .. status .. ' ' .. json)
    SetStatus(status)
    SetHeader('Content-Type', 'application/json')
    SetHeader('Access-Control-Allow-Origin', GetHeader('Origin') or '*')
    SetHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
    SetHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
    SetHeader('Access-Control-Allow-Credentials', 'true')
    Write(json)
end

function parse_query_params()
    local params = {}
    local query = GetUrl():match('?(.+)') or ''
    for k, v in query:gmatch('([^&=]+)=([^&=]*)') do
        params[k] = v
    end
    return params
end

-- Print startup info
print("=== Wallabean Server Started ===")
print("REPL Commands available:")
print("  help() - Show all available commands")
print("  adduser('username', 'password', 'email', 'name') - Add a new user")
print("  makeadmin('username') - Make a user admin (admin API functionality)")
print("  listusers() - List all users")
print("  setloglevel('DEBUG'|'INFO'|'WARN'|'ERROR'|'FATAL') - Set log level")
print("Press Ctrl+C to quit")
print("================================")

-- Open database
db = sqlite3.open('wallabean.db')
db:busy_timeout(1000)

-- Create tables
db:exec[[
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT,
    name TEXT,
    password TEXT,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT UNIQUE,
    client_secret TEXT,
    user_id INTEGER,
    name TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    url TEXT,
    title TEXT,
    content TEXT,
    language TEXT,
    preview_picture TEXT,
    published_at TEXT,
    authors TEXT,
    archived INTEGER DEFAULT 0,
    starred INTEGER DEFAULT 0,
    public INTEGER DEFAULT 0,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

DROP TABLE IF EXISTS access_tokens;
CREATE TABLE access_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE,
    refresh_token TEXT,
    user_id INTEGER,
    client_id INTEGER,
    expires_at TEXT,
    created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
]]

-- Add is_admin column if it doesn't exist (for existing databases)
db:exec[[
ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;
]]

-- Log(kLogInfo, 'Tables created')

function get_log_level()
    local stmt = db:prepare('SELECT value FROM settings WHERE key = ?')
    if stmt then
        stmt:bind(1, 'log_level')
        for row in stmt:nrows() do
            stmt:finalize()
            return tonumber(row.value) or log_levels.INFO
        end
        stmt:finalize()
    end
    return log_levels.INFO
end

function set_log_level(level)
    local stmt = db:prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)')
    if stmt then
        stmt:bind(1, 'log_level')
        stmt:bind(2, tostring(level))
        stmt:step()
        stmt:finalize()
        current_log_level = level
        return true
    end
    return false
end

-- Initialize log level from database
current_log_level = get_log_level()

-- Set redbean's initial log level
local redbean_level = kLogInfo
if current_log_level == log_levels.DEBUG then
    redbean_level = kLogDebug
elseif current_log_level == log_levels.INFO then
    redbean_level = kLogInfo
elseif current_log_level == log_levels.WARN then
    redbean_level = kLogWarn
elseif current_log_level == log_levels.ERROR then
    redbean_level = kLogError
elseif current_log_level == log_levels.FATAL then
    redbean_level = kLogFatal
end
SetLogLevel(redbean_level)

function log_message(level, message)
    if level >= current_log_level then
        Log(kLogInfo, message)
    end
end

function get_entries(filters, user_id)
    local sql = 'SELECT id, user_id, url, title, content, language, preview_picture, published_at, authors, archived, starred, public, created_at, updated_at FROM entries WHERE user_id = ?'
    local args = {user_id}
    
    if filters.archive then
        sql = sql .. ' AND archived = ?'
        table.insert(args, filters.archive)
    end
    if filters.starred then
        sql = sql .. ' AND starred = ?'
        table.insert(args, filters.starred)
    end
    if filters.since and filters.since > 0 then
        sql = sql .. ' AND updated_at > ?'
        table.insert(args, os.date('%Y-%m-%dT%H:%M:%S+0000', filters.since))
    end
    if filters.domain_name then
        sql = sql .. ' AND url LIKE ?'
        table.insert(args, '%' .. filters.domain_name .. '%')
    end
    
    -- Count total
    local count_sql = 'SELECT COUNT(*) FROM entries WHERE user_id = ?'
    local count_args = {user_id}
    if filters.archive then
        count_sql = count_sql .. ' AND archived = ?'
        table.insert(count_args, filters.archive)
    end
    if filters.starred then
        count_sql = count_sql .. ' AND starred = ?'
        table.insert(count_args, filters.starred)
    end
    if filters.since and filters.since > 0 then
        count_sql = count_sql .. ' AND updated_at > ?'
        table.insert(count_args, os.date('%Y-%m-%dT%H:%M:%S+0000', filters.since))
    end
    if filters.domain_name then
        count_sql = count_sql .. ' AND url LIKE ?'
        table.insert(count_args, '%' .. filters.domain_name .. '%')
    end
    
    local count_stmt = db:prepare(count_sql)
    local total = 0
    if count_stmt then
        for i, v in ipairs(count_args) do
            count_stmt:bind(i, v)
        end
        for row in count_stmt:nrows() do
            total = row[1]
            break
        end
        count_stmt:finalize()
    end
    
    local sort_col = filters.sort or 'created_at'
    if sort_col == 'created' then 
        sort_col = 'created_at' 
    elseif sort_col == 'updated' then 
        sort_col = 'updated_at' 
    end
    sql = sql .. ' ORDER BY ' .. sort_col .. ' ' .. (filters.order or 'desc')
    
    local page = filters.page or 1
    local perPage = filters.perPage or 30
    local offset = (page - 1) * perPage
    sql = sql .. ' LIMIT ? OFFSET ?'
    table.insert(args, perPage)
    table.insert(args, offset)
    
    local stmt = db:prepare(sql)
    if not stmt then 
        local empty_results = {}
        setmetatable(empty_results, {__jsontype = "array"})
        return empty_results, 0 
    end
    
    for i, v in ipairs(args) do
        stmt:bind(i, v)
    end
    
    local results = {}
    for row in stmt:nrows() do
        row.headers = {}
        row.is_archived = row.archived
        row.is_starred = row.starred
        row.is_public = row.public == 1
        row.reading_time = 0
        row.tags = {}
        setmetatable(row.tags, {__jsontype = "array"})
        row.user_name = "user"
        row.user_email = "user@example.com"
        row.archived = nil
        row.starred = nil
        row.public = nil
        table.insert(results, row)
    end
    stmt:finalize()
    
    -- Ensure results is always an array
    setmetatable(results, {__jsontype = "array"})
    return results, total
end

-- HTTP content fetching and HTML parsing
function fetch_url_content(url)
    log_message(log_levels.INFO, "Attempting to fetch URL: " .. url)
    
    local status, headers, payload = Fetch(url)
    
    if not status then
        log_message(log_levels.INFO, "Fetch error: " .. tostring(headers))
        return nil, nil, nil, nil
    end
    
    log_message(log_levels.INFO, "Fetch success - status: " .. tostring(status))
    
    if status ~= 200 then
        log_message(log_levels.INFO, "Non-200 status code: " .. tostring(status))
        return nil, nil, nil, nil
    end
    
    if not payload then
        log_message(log_levels.INFO, "No payload in response")
        return nil, nil, nil, nil
    end
    
    log_message(log_levels.DEBUG, "Got HTML content, length: " .. string.len(payload))
    
    -- Extract title from HTML
    local title = payload:match('<title[^>]*>([^<]*)</title>')
    if title then
        title = title:gsub('&amp;', '&'):gsub('&lt;', '<'):gsub('&gt;', '>'):gsub('&quot;', '"'):gsub('&#39;', "'")
        title = title:match('^%s*(.-)%s*$') -- trim whitespace
        log_message(log_levels.DEBUG, "Extracted title: " .. tostring(title))
    else
        log_message(log_levels.DEBUG, "No title found in HTML")
    end
    
    -- Extract content from HTML (remove scripts, styles, and extract text)
    local content = payload
    -- Remove script and style tags
    content = content:gsub('<script[^>]*>.-</script>', '')
    content = content:gsub('<style[^>]*>.-</style>', '')
    -- Remove HTML comments
    content = content:gsub('<!--.--%>', '')
    -- Extract body content if present
    local body_content = content:match('<body[^>]*>(.-)</body>')
    if body_content then
        content = body_content
        log_message(log_levels.DEBUG, "Extracted body content, length: " .. string.len(content))
    else
        log_message(log_levels.DEBUG, "No body tag found, using full content")
    end
    
    -- Extract language from HTML lang attribute
    local language = payload:match('<html[^>]*lang=["\']([^"\']*)["\']') or 
                    payload:match('<html[^>]*xml:lang=["\']([^"\']*)["\']')
    
    -- Extract preview picture from meta tags
    local preview_picture = payload:match('<meta[^>]*property=["\']og:image["\'][^>]*content=["\']([^"\']*)["\']') or
                           payload:match('<meta[^>]*name=["\']twitter:image["\'][^>]*content=[^>]*content=["\']([^"\']*)["\']')
    
    return title, content, language, preview_picture
end

function create_entry(params, user_id)
    local now = get_current_time()
    
    -- If content, title & url are not all provided non-empty, fetch content from URL
    local should_fetch = not (params.content and params.title and params.url and 
                             params.content ~= '' and params.title ~= '')
    
    if should_fetch then
        local fetched_title, fetched_content, fetched_language, fetched_preview = fetch_url_content(params.url)
        if fetched_title then
            params.title = fetched_title
        end
        if fetched_content then
            params.content = fetched_content
        end
        if fetched_language and not params.language then
            params.language = fetched_language
        end
        if fetched_preview and not params.preview_picture then
            params.preview_picture = fetched_preview
        end
    end
    
    local stmt = db:prepare('INSERT INTO entries (user_id, url, title, content, language, preview_picture, published_at, authors, archived, starred, public, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    if not stmt then return nil end
    
    stmt:bind(1, user_id)
    stmt:bind(2, params.url)
    stmt:bind(3, params.title or '')
    stmt:bind(4, params.content or '')
    stmt:bind(5, params.language or '')
    stmt:bind(6, params.preview_picture or '')
    stmt:bind(7, params.published_at or now)
    stmt:bind(8, params.authors or '')
    stmt:bind(9, params.archive and 1 or 0)
    stmt:bind(10, params.starred and 1 or 0)
    stmt:bind(11, params.public and 1 or 0)
    stmt:bind(12, now)
    stmt:bind(13, now)
    
    local res = stmt:step()
    stmt:finalize()
    if res == sqlite3.DONE then
        return db:last_insert_rowid()
    end
    return nil
end

function get_entry(id, user_id)
    local stmt = db:prepare('SELECT * FROM entries WHERE id = ? AND user_id = ?')
    if not stmt then return nil end
    stmt:bind(1, id)
    stmt:bind(2, user_id)
    local row = nil
    for r in stmt:nrows() do
        row = r
        break
    end
    stmt:finalize()
    if row then
        row.headers = {}
        row.is_archived = row.archived
        row.is_starred = row.starred
        row.is_public = row.public == 1
        row.reading_time = 0
        row.tags = {}
        setmetatable(row.tags, {__jsontype = "array"})
        row.user_name = "user"
        row.user_email = "user@example.com"
        row.archived = nil
        row.starred = nil
        row.public = nil
    end
    return row
end

function update_entry(id, params, user_id)
    local now = get_current_time()
    local sql = 'UPDATE entries SET updated_at = ?'
    local args = {now}
    
    if params.title then
        sql = sql .. ', title = ?'
        table.insert(args, params.title)
    end
    if params.content then
        sql = sql .. ', content = ?'
        table.insert(args, params.content)
    end
    if params.language then
        sql = sql .. ', language = ?'
        table.insert(args, params.language)
    end
    if params.preview_picture then
        sql = sql .. ', preview_picture = ?'
        table.insert(args, params.preview_picture)
    end
    if params.published_at then
        sql = sql .. ', published_at = ?'
        table.insert(args, params.published_at)
    end
    if params.authors then
        sql = sql .. ', authors = ?'
        table.insert(args, params.authors)
    end
    if params.archive ~= nil then
        sql = sql .. ', archived = ?'
        table.insert(args, params.archive and 1 or 0)
    end
    if params.starred ~= nil then
        sql = sql .. ', starred = ?'
        table.insert(args, params.starred and 1 or 0)
    end
    if params.public ~= nil then
        sql = sql .. ', public = ?'
        table.insert(args, params.public and 1 or 0)
    end
    
    sql = sql .. ' WHERE id = ? AND user_id = ?'
    table.insert(args, id)
    table.insert(args, user_id)
    
    local stmt = db:prepare(sql)
    if not stmt then return false end
    
    for i, v in ipairs(args) do
        stmt:bind(i, v)
    end
    
    local res = stmt:step()
    stmt:finalize()
    return res == sqlite3.DONE
end

function delete_entry(id, user_id)
    local stmt = db:prepare('DELETE FROM entries WHERE id = ? AND user_id = ?')
    if not stmt then return false end
    stmt:bind(1, id)
    stmt:bind(2, user_id)
    local res = stmt:step()
    stmt:finalize()
    return res == sqlite3.DONE
end

-- OAuth2 functions
function generate_token()
    return 'token_' .. os.time() .. '_' .. math.random(1000000)
end

function generate_csrf_token()
    return 'csrf_' .. os.time() .. '_' .. math.random(1000000)
end

function authenticate_user(username, password)
    local stmt = db:prepare('SELECT id, password FROM users WHERE username = ?')
    if not stmt then return nil end
    stmt:bind(1, username)
    local row = nil
    for r in stmt:nrows() do
        row = r
        break
    end
    stmt:finalize()
    if row and argon2.verify(row.password, password) then
        return row.id
    end
    return nil
end

function validate_client(client_id, client_secret)
     local stmt = db:prepare('SELECT id FROM clients WHERE client_id = ? AND client_secret = ?')
     if not stmt then return nil end
     stmt:bind(1, client_id)
     stmt:bind(2, client_secret)
     local row = nil
     for r in stmt:nrows() do
         row = r
         break
     end
     stmt:finalize()
     return row and row.id
 end

function create_access_token(user_id, client_id)
    log_message(log_levels.DEBUG, 'Creating token for user_id: ' .. tostring(user_id))
    local token = generate_token()
    local refresh_token = generate_token()
    log_message(log_levels.DEBUG, 'Creating token: ' .. token .. ' refresh: ' .. refresh_token)
    local expires_at = os.date('%Y-%m-%dT%H:%M:%S+0000', os.time() + 3600)  -- 1 hour
    local now = get_current_time()
    local stmt = db:prepare('INSERT INTO access_tokens (user_id, client_id, token, refresh_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    if not stmt then
        log_message(log_levels.ERROR, 'Prepare failed')
        return nil
    end
    stmt:bind(1, user_id)
    stmt:bind(2, client_id)
    stmt:bind(3, token)
    stmt:bind(4, refresh_token)
    stmt:bind(5, expires_at)
    stmt:bind(6, now)
    local res = stmt:step()
    stmt:finalize()
    if res == sqlite3.DONE then
        return token, refresh_token
    else
        log_message(log_levels.ERROR, 'Insert failed: ' .. db:errmsg())
        return nil
    end
end

function validate_token(token)
    log_message(log_levels.DEBUG, 'Validating token: ' .. token)
    local stmt = db:prepare('SELECT * FROM access_tokens WHERE token = ?')
    if not stmt then
        log_message(log_levels.ERROR, 'Stmt prepare failed')
        return nil
    end
    stmt:bind(1, token)
    local row = nil
    for r in stmt:nrows() do
        row = r
        log_message(log_levels.DEBUG, 'Found row: ' .. EncodeJson(r))
        break
    end
    stmt:finalize()
     log_message(log_levels.DEBUG, 'Returning user_id: ' .. (row and row["user_id"] or 'nil'))
     return row and row["user_id"]
end

-- Simple session tracking
local sessions = {}

function create_session(user_id)
    local session_id = generate_token()
    local csrf_token = generate_csrf_token()
    sessions[session_id] = {
        user_id = user_id,
        csrf_token = csrf_token,
        expires_at = os.time() + 3600 -- 1 hour
    }
    return session_id, csrf_token
end

function get_session_user(session_id)
    if not session_id then return nil end
    local session = sessions[session_id]
    if session and session.expires_at > os.time() then
        return session.user_id
    end
    if session then
        sessions[session_id] = nil -- cleanup expired
    end
    return nil
end

function validate_csrf_token(submitted_token)
    local cookie_header = GetHeader('Cookie')
    if not cookie_header then return false end
    local session_id = cookie_header:match('session=([^;]+)')
    if not session_id then return false end
    local session = sessions[session_id]
    return session and session.csrf_token == submitted_token
end

function get_current_user()
    local cookie_header = GetHeader('Cookie')
    if not cookie_header then return nil end
    local session_id = cookie_header:match('session=([^;]+)')
    return get_session_user(session_id)
end

function validate_session_cookie()
    local cookie_header = GetHeader('Cookie')
    if not cookie_header then
        return nil
    end
    
    local session_token = cookie_header:match('WALLABEANSESSID=([^;]+)')
    if not session_token then
        return nil
    end
    
    return validate_token(session_token)
end

function require_auth()
    local auth_header = GetHeader('Authorization')
    if not auth_header or not auth_header:match('^Bearer (.+)$') then
        json_response({error = 'invalid_request', error_description = 'Missing or invalid Authorization header'}, 401)
        return false
    end
    local token = auth_header:match('^Bearer (.+)$')
    log_message(log_levels.DEBUG, 'Auth token: ' .. token)
    local user_id = validate_token(token)
    log_message(log_levels.DEBUG, 'User ID: ' .. (user_id or 'nil'))
    if not user_id then
        json_response({error = 'invalid_token', error_description = 'Invalid token'}, 401)
        return false
    end
    return user_id
end

function require_admin()
    local user_id = require_auth()
    if not user_id then return false end
    
    local stmt = db:prepare('SELECT is_admin FROM users WHERE id = ?')
    if not stmt then
        json_response({error = 'Database error'}, 500)
        return false
    end
    
    stmt:bind(1, user_id)
    local is_admin = false
    for row in stmt:nrows() do
        is_admin = row.is_admin == 1
        break
    end
    stmt:finalize()
    
    if not is_admin then
        json_response({error = 'Admin access required'}, 403)
        return false
    end
    
    return user_id
end

function OnHttpRequest()
     local path = GetPath()
     local method = GetMethod()
     log_message(log_levels.INFO, 'Request: ' .. method .. ' ' .. path)
     log_message(log_levels.DEBUG, 'Headers: ' .. EncodeJson(GetHeaders()))
     log_message(log_levels.DEBUG, 'Cookies: ' .. (GetHeader('Cookie') or 'none'))
     if method == 'POST' or method == 'PUT' or method == 'PATCH' then
         local body = GetBody()
         if body and #body > 0 then
             log_message(log_levels.DEBUG, 'Body: ' .. body)
         end
     end

     if method == 'OPTIONS' then
         log_message(log_levels.DEBUG, 'Response: 200 OPTIONS')
         SetStatus(200)
         SetHeader('Allow', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
         SetHeader('Access-Control-Allow-Origin', GetHeader('Origin') or '*')
         SetHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
         SetHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
         SetHeader('Access-Control-Allow-Credentials', 'true')
         return
     end

     -- /api/entries
     if path == '/api/entries' or path == '/api/entries.json' then
        local user_id = require_auth()
        if not user_id then return end
        
        if method == 'GET' then
             local filters = {
                 archive = GetParam('archive'),
                 starred = GetParam('starred'),
                 sort = GetParam('sort'),
                 order = GetParam('order'),
                 page = tonumber(GetParam('page')),
                 perPage = tonumber(GetParam('perPage')),
                 since = tonumber(GetParam('since')),
                 public = GetParam('public'),
                 detail = GetParam('detail'),
                 domain_name = GetParam('domain_name')
             }
             local page = filters.page or 1
             local perPage = filters.perPage or 30
              local entries, total = get_entries(filters, user_id)
              total = total or 0
              perPage = perPage or 30
              
              -- Ensure items is always an array
              if not entries or #entries == 0 then
                  entries = {}
              end
              
              local pages = total > 0 and math.ceil(total / perPage) or 1
              
              local response = {
                  _embedded = {items = entries},
                  total = total,
                  page = page,
                  limit = perPage,
                  pages = pages
              }
              
              -- Force items to be an array in JSON
              if #entries == 0 then
                  SetHeader('Content-Type', 'application/json')
                  Write('{"_embedded":{"items":[]},"total":' .. total .. ',"page":' .. page .. ',"limit":' .. perPage .. ',"pages":' .. pages .. '}')
              else
                  json_response(response)
              end
         elseif method == 'POST' then
             local params = {}
             if GetHeader('Content-Type') == 'application/json' then
                 local body = GetBody()
                 params = DecodeJson(body) or {}
             else
                 params = {
                     url = GetParam('url'),
                     title = GetParam('title'),
                     tags = GetParam('tags'),
                     archive = GetParam('archive'),
                     starred = GetParam('starred'),
                     content = GetParam('content'),
                     language = GetParam('language'),
                     preview_picture = GetParam('preview_picture'),
                     published_at = GetParam('published_at'),
                     authors = GetParam('authors'),
                     public = GetParam('public'),
                     origin_url = GetParam('origin_url')
                 }
             end
            if not params.url then
                json_response({error = 'URL is required'}, 400)
                return
            end
            local id = create_entry(params, user_id)
            if id then
                local entry = get_entry(id, user_id)
                if entry then
                    json_response(entry, 200)
                else
                    json_response({error = 'Failed to retrieve entry'}, 500)
                end
            else
                json_response({error = 'Failed to create entry'}, 500)
            end
        else
            ServeError(405)
        end
     -- /api/entries/exists
      elseif path == '/api/entries/exists' or path == '/api/entries/exists.json' then
          if method == 'GET' then
              local hashed_url = GetParam('hashed_url')
              local url = GetParam('url')  -- deprecated
              local return_id = GetParam('return_id') == '1'
              local target_url = hashed_url or url
              if not target_url then
                  json_response({error = 'URL or hashed_url required'}, 400)
                  return
              end
              local stmt = db:prepare('SELECT id FROM entries WHERE url = ?')
              if not stmt then
                  json_response({error = 'DB error'}, 500)
                  return
              end
              stmt:bind(1, target_url)
              local exists = false
              local id = nil
              for row in stmt:nrows() do
                  exists = true
                  id = row[1]
                  break
              end
              stmt:finalize()
              if return_id then
                  json_response(exists and id or false)
              else
                  json_response({exists = exists})
              end
          else
              json_response({error = 'Method not allowed'}, 405)
          end
     -- /api/entries/{id}
     elseif path:match('/api/entries/(%d+)') or path:match('/api/entries/(%d+).json') then
        local user_id = require_auth()
        if not user_id then return end
        
        local id = tonumber(path:match('/api/entries/(%d+)'))
        if method == 'GET' then
            local entry = get_entry(id, user_id)
            if entry then
                json_response(entry)
            else
                json_response({error = 'Entry not found'}, 404)
            end
        elseif method == 'PATCH' then
            local params = {
                title = GetParam('title'),
                tags = GetParam('tags'),
                archive = GetParam('archive'),
                starred = GetParam('starred'),
                content = GetParam('content'),
                language = GetParam('language'),
                preview_picture = GetParam('preview_picture'),
                published_at = GetParam('published_at'),
                authors = GetParam('authors'),
                public = GetParam('public'),
                origin_url = GetParam('origin_url')
            }
            if update_entry(id, params, user_id) then
                json_response({success = true})
            else
                json_response({error = 'Failed to update entry'}, 500)
            end
        elseif method == 'DELETE' then
            if delete_entry(id, user_id) then
                json_response({success = true})
            else
                json_response({error = 'Failed to delete entry'}, 500)
            end
        else
            ServeError(405)
        end
    -- /api/config
    elseif path == '/api/config' then
        if method == 'GET' then
            json_response({config = 'mock config'})
        else
            ServeError(405)
        end
     -- /api/version
     elseif path == '/api/version' or path == '/api/version.json' then
         if method == 'GET' then
             json_response('2.5.2')
         else
             json_response({error = 'Method not allowed'}, 405)
         end
    -- /api/info
    elseif path == '/api/info' then
        if method == 'GET' then
             json_response({
                 appname = 'wallabag',
                 version = '2.5.2',
                 allowed_registration = false
             })
        else
            ServeError(405)
        end
     -- /api/user
     elseif path == '/api/user' or path == '/api/user.json' then
         local user_id = require_auth()
         if not user_id then return end
         
         if method == 'GET' then
             local stmt = db:prepare('SELECT id, username, email, name, created_at, updated_at FROM users WHERE id = ?')
             if stmt then
                 stmt:bind(1, user_id)
                 local user = nil
                 for row in stmt:nrows() do
                     user = row
                     break
                 end
                 stmt:finalize()
                 if user then
                     json_response(user)
                 else
                     json_response({error = 'User not found'}, 404)
                 end
             else
                 json_response({error = 'DB error'}, 500)
             end
         elseif method == 'PUT' then
             json_response({error = 'Registration not allowed'}, 403)
         else
             ServeError(405)
         end
    -- /api/tags
    elseif path == '/api/tags' or path == '/api/tags.json' then
        if method == 'GET' then
            local stmt = db:prepare('SELECT * FROM tags')
            local tags = {}
            for row in stmt:nrows() do
                table.insert(tags, row)
            end
            stmt:finalize()
            json_response(tags)
        else
            ServeError(405)
        end
    -- /api/search
     elseif path == '/api/search' then
         if method == 'GET' then
             local term = GetParam('term')
             local page = tonumber(GetParam('page')) or 1
             local perPage = tonumber(GetParam('perPage')) or 30
             -- Count total
             local count_sql = 'SELECT COUNT(*) FROM entries WHERE title LIKE ? OR content LIKE ?'
             local count_stmt = db:prepare(count_sql)
             local total = 0
             if count_stmt then
                 count_stmt:bind(1, '%' .. (term or '') .. '%')
                 count_stmt:bind(2, '%' .. (term or '') .. '%')
                 for row in count_stmt:nrows() do
                     total = row[1]
                     break
                 end
                 count_stmt:finalize()
             end
             -- Simple search in title and content
             local sql = 'SELECT * FROM entries WHERE title LIKE ? OR content LIKE ? LIMIT ? OFFSET ?'
             local stmt = db:prepare(sql)
             if stmt then
                 stmt:bind(1, '%' .. (term or '') .. '%')
                 stmt:bind(2, '%' .. (term or '') .. '%')
                 stmt:bind(3, perPage)
                 stmt:bind(4, (page - 1) * perPage)
                 local results = {}
                 for row in stmt:nrows() do
                     table.insert(results, row)
                 end
                 stmt:finalize()
                 json_response({
                     entries = results,
                     total = total,
                     page = page,
                     limit = perPage,
                     pages = math.ceil(total / perPage)
                 })
             else
                 json_response({entries = {}, total = 0, page = page, limit = perPage, pages = 0})
             end
         else
             ServeError(405)
         end
    -- /api/admin/users
    elseif path == '/api/admin/users' and method == 'POST' then
        local user_id = require_admin()
        if not user_id then return end
        
        local username = GetParam('username')
        local password = GetParam('password')
        local email = GetParam('email')
        local name = GetParam('name')
        local is_admin = GetParam('is_admin') == 'true' or GetParam('is_admin') == '1'
        
        if not username or not password or not email then
            json_response({error = 'Missing required fields'}, 400)
            return
        end
        
        local salt = 'salt_' .. math.random(1000000000)
        local hashed_password = argon2.hash_encoded(password, salt)
        if not hashed_password then
            json_response({error = 'Password hashing failed'}, 500)
            return
        end
        
        local stmt = db:prepare('INSERT INTO users (username, email, name, password, is_admin, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        if stmt then
            local now = get_current_time()
            stmt:bind(1, username)
            stmt:bind(2, email)
            stmt:bind(3, name or '')
            stmt:bind(4, hashed_password)
            stmt:bind(5, is_admin and 1 or 0)
            stmt:bind(6, now)
            stmt:bind(7, now)
            local res = stmt:step()
            stmt:finalize()
            if res == sqlite3.DONE then
                json_response({success = true, id = db:last_insert_rowid()})
            else
                json_response({error = 'Failed to create user'}, 500)
            end
        else
            json_response({error = 'DB error'}, 500)
        end
     -- /api/admin/clients
     elseif path == '/api/admin/clients' and method == 'POST' then
         local user_id = require_admin()
         if not user_id then return end
         
         local target_user_id = GetParam('user_id')
         local client_name = GetParam('client_name')
         if not target_user_id or not client_name then
             json_response({error = 'Missing required fields'}, 400)
             return
         end
         local client_id = 'client_' .. math.random(1000000)
         local client_secret = 'secret_' .. math.random(1000000)
         local stmt = db:prepare('INSERT INTO clients (client_id, client_secret, user_id, name) VALUES (?, ?, ?, ?)')
         if stmt then
             stmt:bind(1, client_id)
             stmt:bind(2, client_secret)
             stmt:bind(3, target_user_id)
             stmt:bind(4, client_name)
             local res = stmt:step()
             stmt:finalize()
             if res == sqlite3.DONE then
                 json_response({success = true, client_id = client_id, client_secret = client_secret})
             else
                 json_response({error = 'Failed to create client'}, 500)
             end
         else
             json_response({error = 'DB error'}, 500)
         end
     -- /api/admin/tokens
     elseif path == '/api/admin/tokens' and method == 'GET' then
         local user_id = require_admin()
         if not user_id then return end
         
          local stmt = db:prepare('SELECT token, refresh_token, user_id, client_id, expires_at, created_at FROM access_tokens')
          if stmt then
              local tokens = {}
              for row in stmt:nrows() do
                  table.insert(tokens, row)
              end
              stmt:finalize()
              json_response(tokens)
          else
              json_response({error = 'DB error'}, 500)
          end
     -- /developer/client/create
     elseif path == '/developer/client/create' then
         if method == 'GET' then
             local temp_csrf = generate_csrf_token()
             SetHeader('Content-Type', 'text/html')
             Write([[<!DOCTYPE html>
<html>
<head>
    <title>Create API Client - wallabean</title>
</head>
<body>
    <h1>Create a new API client</h1>
    <form method="post">
        <input type="hidden" id="client__token" name="client[_token]" value="]] .. temp_csrf .. [[" />
        <input type="text" name="client[name]" placeholder="Client name" required>
        <input type="submit" value="Create client">
    </form>
</body>
</html>]])
         elseif method == 'POST' then
             local csrf_token = GetParam('client[_token]')
             if not validate_csrf_token(csrf_token) then
                 SetStatus(403)
                 Write('Invalid CSRF token')
                 return
             end
             
             local client_name = GetParam('client[name]') or GetParam('name') or 'Android app'
             
             -- Get user ID
             local user_id = get_current_user()
             if not user_id then
                 local stmt = db:prepare('SELECT id FROM users ORDER BY id LIMIT 1')
                 if stmt then
                     for row in stmt:nrows() do
                         user_id = row.id
                         break
                     end
                     stmt:finalize()
                 end
             end
             
             if not user_id then
                 SetStatus(400)
                 Write('No user found')
                 return
             end
             
             -- Check if user already has a client with this name
             local check_stmt = db:prepare('SELECT client_id, client_secret FROM clients WHERE user_id = ? AND name = ? LIMIT 1')
             local existing_client = nil
             if check_stmt then
                 check_stmt:bind(1, user_id)
                 check_stmt:bind(2, client_name)
                 for row in check_stmt:nrows() do
                     existing_client = row
                     break
                 end
                 check_stmt:finalize()
             end
             
             local client_id, client_secret
             if existing_client then
                 -- Return existing client
                 client_id = existing_client.client_id
                 client_secret = existing_client.client_secret
             else
                 -- Create new client
                 client_id = 'client_' .. math.random(1000000)
                 client_secret = 'secret_' .. math.random(1000000)
                 
                 local stmt = db:prepare('INSERT INTO clients (client_id, client_secret, user_id, name) VALUES (?, ?, ?, ?)')
                 if stmt then
                     stmt:bind(1, client_id)
                     stmt:bind(2, client_secret)
                     stmt:bind(3, user_id)
                     stmt:bind(4, client_name)
                     stmt:step()
                     stmt:finalize()
                 end
             end
             
             SetHeader('Content-Type', 'text/html')
             Write([[<!DOCTYPE html>
<html>
<head>
    <title>API Client Created - wallabean</title>
</head>
<body>
    <h1>API client created successfully</h1>
    <ul>
        <li>Client ID: <strong><pre>]] .. client_id .. [[</pre></strong></li>
        <li>Client secret: <strong><pre>]] .. client_secret .. [[</pre></strong></li>
        <li>Redirect URIs: <strong><pre></pre></strong></li>
    </ul>
</body>
</html>]])
         else
             ServeError(405)
         end
     -- /developer
     elseif path == '/developer' then
         if method == 'GET' then
             local html = [[<!DOCTYPE html>
<html>
<head>
    <title>Developer - wallabean</title>
</head>
<body>
    <h1>API clients management</h1>]]
             
             -- Show actual clients from database
             local stmt = db:prepare('SELECT id, client_id, client_secret, name FROM clients ORDER BY id')
             if stmt then
                 for row in stmt:nrows() do
                     html = html .. [[
    <div class="collapsible-header">]] .. row.name .. [[ - #]] .. row.id .. [[</div>
    <p>Client ID: <strong><code>]] .. row.client_id .. [[</code></strong></p>
    <p>Client secret: <strong><code>]] .. row.client_secret .. [[</code></strong></p>
    <p>Redirect URIs: <strong><code></code></strong></p>
    <p>Grant types allowed: <strong><code>password refresh_token</code></strong></p>
    <a href="/developer/client/delete/">Delete</a>]]
                 end
                 stmt:finalize()
             end
             
             -- Add the "Other client" that was in the working version
             html = html .. [[
    <div class="collapsible-header">Other client</div>
    <p>Client ID: <strong><code>other</code></strong></p>
    <p>Client secret: <strong><code>othersecret</code></strong></p>
    <p>Redirect URIs: <strong><code></code></strong></p>
    <p>Grant types allowed: <strong><code>password</code></strong></p>
    <a href="/developer/client/delete/">Delete</a>
    <a href="/developer/client/delete/">Delete</a>]]
             
             html = html .. [[
</body>
</html>]]
             
             log_message(log_levels.INFO, 'Developer page HTML: ' .. html)
             SetHeader('Content-Type', 'text/html')
             Write(html)
         else
             ServeError(405)
         end
     -- /logout
     elseif path == '/logout' then
         if method == 'GET' then
             -- Clear session cookie and redirect
             SetHeader('Set-Cookie', 'session=; Path=/; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
             SetHeader('Content-Type', 'text/html')
             Write([[<!DOCTYPE html>
<html>
<head>
    <title>Logged Out</title>
    <meta http-equiv="refresh" content="0; url=/">
</head>
<body>
    <p>Logged out. Redirecting...</p>
    <script>window.location.href = '/';</script>
</body>
</html>]])
         else
             ServeError(405)
         end
     -- /login_check
     elseif path == '/login_check' then
         if method == 'POST' then
             local username = GetParam('_username')
             local password = GetParam('_password')
             
             if not username or not password then
                 json_response({error = 'Missing username or password'}, 400)
                 return
             end
             
             local user_id = authenticate_user(username, password)
             if user_id then
                 local session_id, csrf_token = create_session(user_id)
                 SetHeader('Set-Cookie', 'session=' .. session_id .. '; Path=/; HttpOnly; SameSite=Lax')
                 SetHeader('Content-Type', 'text/html')
                 Write([[<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta http-equiv="refresh" content="0; url=/">
</head>
<body>
    <p>Login successful. Redirecting...</p>
    <script>window.location.href = '/';</script>
</body>
</html>]])
             else
                 json_response({error = 'Invalid credentials'}, 401)
             end
         else
             ServeError(405)
         end
     -- /oauth/v2/token
     elseif path == '/oauth/v2/token' then
         local grant_type, username, password, client_id, client_secret
          local params = {}
          if method == 'POST' and GetHeader('Content-Type') == 'application/json' then
              local body = GetBody()
              params = DecodeJson(body) or {}
          else
              params.grant_type = GetParam('grant_type')
              params.username = GetParam('username')
              params.password = GetParam('password')
              params.client_id = GetParam('client_id')
              params.client_secret = GetParam('client_secret')
          end
          local grant_type = params.grant_type
          local username = params.username
          local password = params.password
          local client_id = params.client_id
          local client_secret = params.client_secret

          if grant_type == 'refresh_token' then
              local refresh_token = params.refresh_token
              if not refresh_token then
                  json_response({error = 'invalid_request', error_description = 'Missing refresh_token'}, 400)
                  return
              end
              -- validate refresh_token
              local stmt = db:prepare('SELECT user_id, client_id FROM access_tokens WHERE refresh_token = ?')
              if not stmt then
                  json_response({error = 'server_error'}, 500)
                  return
              end
              stmt:bind(1, refresh_token)
              local row = nil
              for r in stmt:nrows() do
                  row = r
                  break
              end
              stmt:finalize()
              if not row then
                  json_response({error = 'invalid_grant', error_description = 'Invalid refresh token'}, 401)
                  return
              end
              local user_id = row.user_id
              local client_id = row.client_id
              -- create new token
              local new_token, new_refresh = create_access_token(user_id, client_id)
              if not new_token then
                  json_response({error = 'server_error'}, 500)
                  return
              end
              -- update the row with new token
              local update_stmt = db:prepare('UPDATE access_tokens SET token = ?, expires_at = ? WHERE refresh_token = ?')
              if update_stmt then
                  local new_expires = os.date('%Y-%m-%dT%H:%M:%S+0000', os.time() + 3600)
                  update_stmt:bind(1, new_token)
                  update_stmt:bind(2, new_expires)
                  update_stmt:bind(3, refresh_token)
                  update_stmt:step()
                  update_stmt:finalize()
              end
              json_response({
                  access_token = new_token,
                  refresh_token = refresh_token,
                  token_type = 'Bearer',
                  expires_in = 3600
              })
              return
          elseif grant_type ~= 'password' then
              json_response({error = 'unsupported_grant_type', error_description = 'Unsupported grant type'}, 400)
              return
          end

          Log(kLogInfo, 'Login attempt: username=' .. (username or 'nil') .. ' client_id=' .. (client_id or 'nil'))
          log_message(log_levels.DEBUG, 'validating client: ' .. (client_id or 'nil') .. ' ' .. (client_secret or 'nil'))
          local client_valid = validate_client(client_id, client_secret)
          log_message(log_levels.DEBUG, 'client_valid: ' .. (client_valid or 'nil'))
          if not client_valid then
              json_response({error = 'invalid_client', error_description = 'Invalid client credentials'}, 401)
              return
          end
         
         local user_id = authenticate_user(username, password)
         log_message(log_levels.DEBUG, 'Authenticated user_id: ' .. (user_id or 'nil'))
         if not user_id then
             json_response({error = 'invalid_grant', error_description = 'Invalid username or password'}, 401)
             return
         end
         
         local token, refresh_token = create_access_token(user_id, client_valid)
         if token then
            json_response({
                access_token = token,
                refresh_token = refresh_token,
                token_type = 'Bearer',
                expires_in = 3600
            })
        else
            json_response({error = 'Failed to create token'}, 500)
          end
     else
         -- Main page and other paths
         if path == '/' then
             local current_user = get_current_user()
             
             -- Always show the same page with logo and logout link
             SetHeader('Content-Type', 'text/html')
             Write([[<!DOCTYPE html>
<html>
<head>
    <title>wallabean</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/png" href="logo-small.png">
</head>
<body>
    <div class="center">
        <img src="logo-small.png" class="typo-logo" alt="wallabag logo" />
    </div>
    <h1>Wallabean</h1>
    ]])
    
    if current_user then
        -- Get user details for personalized welcome
        local stmt = db:prepare('SELECT username, name, email FROM users WHERE id = ?')
        local user_info = nil
        if stmt then
            stmt:bind(1, current_user)
            for row in stmt:nrows() do
                user_info = row
                break
            end
            stmt:finalize()
        end
        
        if user_info then
            local display_name = user_info.name and user_info.name ~= '' and user_info.name or user_info.username
            Write('<p>Welcome back, <strong>' .. display_name .. '</strong>!</p>')
            Write('<p>You are logged in as: ' .. user_info.username .. '</p>')
        else
            Write('<p>Welcome to wallabean!</p>')
        end
        
        Write('<a href="/logout">log out</a>')
        
        -- Add Get Entries JSON button
        Write([[
    <div style="margin-top: 20px; border: 1px solid #ccc; padding: 10px;">
        <h3>API Test</h3>
        <div style="margin: 10px 0;">
            <input type="text" id="client-id" placeholder="Client ID" style="width: 150px; padding: 5px;">
            <input type="text" id="client-secret" placeholder="Client Secret" style="width: 150px; padding: 5px;">
            <input type="text" id="username" placeholder="Username" value="]] .. (user_info and user_info.username or '') .. [[" style="width: 100px; padding: 5px;">
            <input type="password" id="password" placeholder="Password" style="width: 100px; padding: 5px;">
            <button onclick="getToken()">Get Token</button>
        </div>
        <button onclick="getEntries()">Get Entries JSON</button>
        <pre id="entries-result" style="background: #f5f5f5; padding: 10px; margin-top: 10px; display: none;"></pre>
    </div>
    
    <script>
    async function getToken() {
        const clientId = document.getElementById('client-id').value;
        const clientSecret = document.getElementById('client-secret').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        if (!clientId || !clientSecret || !username || !password) {
            alert('Please fill in all fields');
            return;
        }
        
        try {
            const response = await fetch('/oauth/v2/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    grant_type: 'password',
                    client_id: clientId,
                    client_secret: clientSecret,
                    username: username,
                    password: password
                })
            });
            
            const data = await response.json();
            if (data.access_token) {
                localStorage.setItem('wallabean_token', data.access_token);
                alert('Token obtained and saved!');
            } else {
                alert('Error: ' + JSON.stringify(data));
            }
        } catch (error) {
            alert('Error: ' + error.message);
        }
    }
    
    async function getEntries() {
        const resultDiv = document.getElementById('entries-result');
        resultDiv.style.display = 'block';
        resultDiv.textContent = 'Loading...';
        
        const token = getStoredToken();
        if (token === 'no-token-available') {
            resultDiv.textContent = 'Error: No token available. Please get a token first using your client credentials.';
            return;
        }
        
        try {
            const response = await fetch('/api/entries', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json'
                }
            });
            
            const data = await response.json();
            resultDiv.textContent = JSON.stringify(data, null, 2);
        } catch (error) {
            resultDiv.textContent = 'Error: ' + error.message;
        }
    }
    
    function getStoredToken() {
        return localStorage.getItem('wallabean_token') || 'no-token-available';
    }
    </script>]])
        
        -- Show QR code with actual username
        if user_info then
            Write([[
    <!-- Android Configuration -->
    <div style="margin-top: 20px; border: 1px solid #ccc; padding: 10px;">
        <h3>Android Configuration</h3>
        <p>Scan this QR code with the wallabag Android app:</p>
        <div id="qrcode" style="margin: 10px 0;"></div>
        <br>
        <p>Or use this URL manually:</p>
        <code>wallabag://]] .. user_info.username .. [[@]] .. GetHeader('Host') .. [[</code>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/qrious@4.0.2/dist/qrious.min.js"></script>
    <script>
        // Generate QR code when page loads
        const qrText = 'wallabag://]] .. user_info.username .. [[@]] .. GetHeader('Host') .. [[';
        const canvas = document.createElement('canvas');
        document.getElementById('qrcode').appendChild(canvas);
        
        new QRious({
            element: canvas,
            value: qrText,
            size: 200,
            background: 'white',
            foreground: 'black'
        });
    </script>
            ]])
        end
    else
        -- Show login form when not logged in
        local temp_csrf = generate_csrf_token()
        Write([[
    <p>Welcome to wallabean!</p>
    <!-- Login form -->
    <div style="margin-top: 20px; border: 1px solid #ccc; padding: 10px;">
        <h3>Login</h3>
        <form action="/login_check" method="post" name="loginform">
            <div style="margin: 10px 0;">
                <input type="text" name="_username" placeholder="Username" required style="padding: 8px; width: 200px;">
            </div>
            <div style="margin: 10px 0;">
                <input type="password" name="_password" placeholder="Password" required style="padding: 8px; width: 200px;">
            </div>
            <input type="hidden" name="_csrf_token" value="]] .. temp_csrf .. [[" />
            <input type="submit" value="Login" style="padding: 8px 16px;">
        </form>
    </div>
        ]])
    end
    
    Write([[
</body>
</html>]])
         else
             -- For other paths, serve static or 404
             log_message(log_levels.DEBUG, 'Serving static or 404 for ' .. path)
             Route()
         end
     end
end

-- REPL functions for user management
function query(sql)
    local stmt = db:prepare(sql)
    if not stmt then
        print("Error: " .. db:errmsg())
        return
    end
    for row in stmt:nrows() do
        print(EncodeJson(row))
    end
    stmt:finalize()
end

function adduser(username, password, email, name, is_admin)
    if not username or not password then
        print("Usage: adduser('username', 'password', 'email', 'name', is_admin)")
        print("Example: adduser('john', 'secret123', 'john@example.com', 'John Doe', true)")
        print("  is_admin: true/false (optional, defaults to false)")
        return false
    end
    
    email = email or (username .. '@example.com')
    name = name or username
    is_admin = is_admin or false
    
    local salt = 'salt_' .. math.random(1000000000)
    local hashed_password = argon2.hash_encoded(password, salt)
    if not hashed_password then
        print("Password hashing failed")
        return false
    end
    
    local now = get_current_time()
    local stmt = db:prepare('INSERT INTO users (username, email, name, password, is_admin, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    if not stmt then
        print("Database error: " .. db:errmsg())
        return false
    end
    
    stmt:bind(1, username)
    stmt:bind(2, email)
    stmt:bind(3, name)
    stmt:bind(4, hashed_password)
    stmt:bind(5, is_admin and 1 or 0)
    stmt:bind(6, now)
    stmt:bind(7, now)
    
    local res = stmt:step()
    stmt:finalize()
    
    if res == sqlite3.DONE then
        local user_id = db:last_insert_rowid()
        print("User created successfully!")
        print("  ID: " .. user_id)
        print("  Username: " .. username)
        print("  Email: " .. email)
        print("  Name: " .. name)
        print("  Admin: " .. (is_admin and "Yes" or "No"))
        return true
    else
        print("Failed to create user: " .. db:errmsg())
        return false
    end
end

function makeadmin(username)
    if not username then
        print("Usage: makeadmin('username')")
        print("Example: makeadmin('alice')")
        return false
    end
    
    local stmt = db:prepare('UPDATE users SET is_admin = 1 WHERE username = ?')
    if not stmt then
        print("Database error: " .. db:errmsg())
        return false
    end
    
    stmt:bind(1, username)
    local res = stmt:step()
    stmt:finalize()
    
    if res == sqlite3.DONE then
        if db:changes() > 0 then
            print("User '" .. username .. "' is now an admin")
            return true
        else
            print("User '" .. username .. "' not found")
            return false
        end
    else
        print("Failed to update user: " .. db:errmsg())
        return false
    end
end

function createclient(username, client_name)
    if not username then
        print("Usage: createclient('username', 'client_name')")
        print("Example: createclient('joris', 'Android App')")
        return false
    end
    
    client_name = client_name or 'Default Client'
    
    -- Get user ID
    local stmt = db:prepare('SELECT id FROM users WHERE username = ?')
    if not stmt then
        print("Database error: " .. db:errmsg())
        return false
    end
    
    stmt:bind(1, username)
    local user_id = nil
    for row in stmt:nrows() do
        user_id = row.id
        break
    end
    stmt:finalize()
    
    if not user_id then
        print("User '" .. username .. "' not found")
        return false
    end
    
    -- Create client
    local client_id = 'client_' .. math.random(1000000)
    local client_secret = 'secret_' .. math.random(1000000)
    
    local stmt2 = db:prepare('INSERT INTO clients (client_id, client_secret, user_id, name) VALUES (?, ?, ?, ?)')
    if not stmt2 then
        print("Database error: " .. db:errmsg())
        return false
    end
    
    stmt2:bind(1, client_id)
    stmt2:bind(2, client_secret)
    stmt2:bind(3, user_id)
    stmt2:bind(4, client_name)
    
    local res = stmt2:step()
    stmt2:finalize()
    
    if res == sqlite3.DONE then
        print("Client created successfully!")
        print("  Client ID: " .. client_id)
        print("  Client Secret: " .. client_secret)
        print("  User: " .. username)
        print("  Name: " .. client_name)
        return true
    else
        print("Failed to create client: " .. db:errmsg())
        return false
    end
end

function removeadmin(username)
    if not username then
        print("Usage: removeadmin('username')")
        print("Example: removeadmin('alice')")
        return false
    end
    
    local stmt = db:prepare('UPDATE users SET is_admin = 0 WHERE username = ?')
    if not stmt then
        print("Database error: " .. db:errmsg())
        return false
    end
    
    stmt:bind(1, username)
    local res = stmt:step()
    stmt:finalize()
    
    if res == sqlite3.DONE then
        if db:changes() > 0 then
            print("User '" .. username .. "' is no longer an admin")
            return true
        else
            print("User '" .. username .. "' not found")
            return false
        end
    else
        print("Failed to update user: " .. db:errmsg())
        return false
    end
end

function listusers()
    local stmt = db:prepare('SELECT id, username, email, name, is_admin, created_at FROM users ORDER BY id')
    if not stmt then
        print("Database error: " .. db:errmsg())
        return
    end
    
    print("Users:")
    print("ID | Username | Email | Name | Admin | Created")
    print("---|----------|-------|------|-------|--------")
    
    for row in stmt:nrows() do
        print(string.format("%d | %s | %s | %s | %s | %s", 
            row.id, row.username, row.email, row.name, 
            (row.is_admin == 1 and "Yes" or "No"), row.created_at))
    end
    stmt:finalize()
end

function setloglevel(level)
    local level_name = level
    local level_num
    
    if type(level) == 'string' then
        level_name = level:upper()
        level_num = log_levels[level_name]
    elseif type(level) == 'number' then
        level_num = level
        for name, num in pairs(log_levels) do
            if num == level then
                level_name = name
                break
            end
        end
    end
    
    if not level_num then
        print("Invalid log level. Valid levels are:")
        for name, num in pairs(log_levels) do
            print("  " .. name .. " (" .. num .. ")")
        end
        return false
    end
    
    -- Set redbean's log level
    local redbean_level = kLogInfo
    if level_num == log_levels.DEBUG then
        redbean_level = kLogDebug
    elseif level_num == log_levels.INFO then
        redbean_level = kLogInfo
    elseif level_num == log_levels.WARN then
        redbean_level = kLogWarn
    elseif level_num == log_levels.ERROR then
        redbean_level = kLogError
    elseif level_num == log_levels.FATAL then
        redbean_level = kLogFatal
    end
    SetLogLevel(redbean_level)
    
    if set_log_level(level_num) then
        print("Log level set to " .. level_name .. " (" .. level_num .. ")")
        return true
    else
        print("Failed to set log level")
        return false
    end
end

function help()
    print("Wallabean REPL Commands:")
    print("")
    print("User Management:")
    print("  adduser('username', 'password', 'email', 'name', is_admin)")
    print("    - Add a new user (email, name, and is_admin are optional)")
    print("    - Example: adduser('alice', 'secret123', 'alice@example.com', 'Alice Smith', true)")
    print("    - is_admin: true for admin users, false for regular users")
    print("")
    print("  listusers()")
    print("    - List all users in the database with admin status")
    print("")
    print("  makeadmin('username')")
    print("    - Promote a user to admin")
    print("    - Example: makeadmin('alice')")
    print("")
    print("  removeadmin('username')")
    print("    - Remove admin privileges from a user")
    print("    - Example: removeadmin('alice')")
    print("")
    print("Client Management:")
    print("  createclient('username', 'client_name')")
    print("    - Create an API client for a user")
    print("    - Example: createclient('joris', 'Android App')")
    print("")
    print("Logging:")
    print("  setloglevel('DEBUG'|'INFO'|'WARN'|'ERROR'|'FATAL')")
    print("    - Set the logging level (stored in database)")
    print("    - Example: setloglevel('DEBUG') or setloglevel(0)")
    print("    - Current level: " .. current_log_level)
    print("")
    print("Database:")
    print("  query('SELECT * FROM users')")
    print("    - Run any SQL SELECT query and display results")
    print("  db - SQLite database connection")
    print("  You can run raw SQL: db:exec('SELECT * FROM users')")
    print("")
    print("Server:")
    print("  Access logs and debug info are available in the console")
    print("  Use Ctrl+C to exit the REPL")
end
local T = require"framework"

local discordia = require"discordia"
local http = require"coro-http"
local qs = require"querystring"
local json = require"json"
local b64 = plugin:unloadableSource"gh/b64"
local sleep = require"timer".sleep

local lpeg = require"lpeg"
local Logger = discordia.Logger(3, '%F %T')

local wrap = coroutine.wrap
local insert = table.insert
local encode,decode = json.encode,json.decode
local date, time, difftime = os.date, os.time, os.difftime

local Mutex = discordia.Mutex
local Base = T.Object:extend{}:mix(T.Callable)

local function parseDate(str)
	local _, day, month, year, hour, min, sec = str:match(
		'(%a-), (%d-) (%a-) (%d-) (%d-):(%d-):(%d-) GMT'
	)
	local serverDate = {
		day = day, month = months[month], year = year,
		hour = hour, min = min, sec = sec,
	}
	local clientDate = date('!*t')
	clientDate.isdst = date('*t').isdst
	return difftime(time(serverDate), time(clientDate)) + time()
end

local Github = Base:extend{
	__info = "github-client",
	__root = "https://api.github.com"
}

function Github:initial(TOKEN, agent)
	self._mutex = Mutex()
	self._maxRetries = 5
	self._headers = {
		{"Authorization","Basic "..b64(TOKEN)}
		,{"User-Agent", agent}
	}
end

local usingPayload = {
    DELETE = true,
    PUT = true,
    PATCH = true,
    POST = true,
}

local function makeurl (self,endp,query)
    return ("%s%s?%s"):format(self.__root,endp, query and qs.stringify(query) or '') 
end

local function getHeaders(resp)
    local hd = {}
    for i,h in ipairs(resp) do
      hd[h[1]] = h[2]
    end
    return hd
end

function Github:_method( restmethod, endpoint, query, payload )
    
	if usingPayload[restmethod] then
		payload = payload and encode(payload) or '{}'
		insert(headers,{'Content-Type','application/json'})
		insert(headers,{'Content-Length',#payload})
	end
	local routex = self._mutex
	local url = makeurl(self,endpoint,query)
	routex:lock()
	local res, data, reason, delay = self:push(restmethod,url,self._headers,payload,routex,1)
	routex:unlockAfter(delay)
	return res, data, reason
end

function Github:push (method,url,headers,payload,routex,attempts)
    local isRetrying = attempts > 1
    local delay = 300
    
	local succ,res,msg = pcall(http.request,method,url,headers,payload)
	if not succ and attempts <= self._maxRetries then 
		sleep(100)
		return self:push(method, url, headers, payload, routex, attempts + 1)
	elseif not succ and attempts > self._maxRetries then 
		return nil, res.code, res.reason, delay 
	end
	local headers = getHeaders(res)
    local reset, remaining = headers['X-RateLimit-Reset'], headers['X-RateLimit-Remaining']

	if reset and remaining == '0' then
		local dt = difftime(reset, parseDate(res.date))
		delay = max(dt, delay)
	end
	local data = decode(msg) or msg
	if res.code < 300 then 
		return res, data, nil, delay
	else
		return nil,res.code, msg, delay
	end
    
end


function Github:get(endpoint, query)
	return self:_method("GET", endpoint, query)
end


function Github:search_code(term, lang)
	local q = term .. "+in:file"   .. (lang and "+language:"..lang or "")
	return self:get("/search/code", {q = q})
end

function Github:request(url, method)
	local routex = self._mutex
	routex:lock()
	local res, data, reason, delay = self:push(method or "GET",url,self._headers,nil,routex,1)
	routex:unlockAfter(delay)
	return res, data, reason
end

-- if anyone wants to add more stuff that'd be awesome

return Github
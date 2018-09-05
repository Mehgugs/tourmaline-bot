local lpeg = require("lpeg")
      lpeg.locale(lpeg)

local function exactly(n, p) 
    local patt = lpeg.P(p)
    local out = patt
    for i = 1, n-1 do 
        out = out * patt
    end
    return out
end
local function nothing(p) return lpeg.P(p) end
local function just(p) return  lpeg.P(p) * -1 end
local function truth() return true end
local function check(p) return  lpeg.P(p)/truth end 
local function sepby(s, p) return p * (s * p)^0 end
local function between(b, s) return  b * ((s * b)^1) end
local function zipWith(f, ...) local p = f((...)) 
    for _, q in ipairs{select(2, ...)} do 
        p = p * f(q) 
    end
    return p
end
local function some(p) return  lpeg.P(p)^1 end
local function optionally(p) return  lpeg.P(p)^-1 end
local function bracket(p) return "(" *  lpeg.P(p) * ")" end
local hash = lpeg.P("#")
local ropen = lpeg.P"[["
local rclosed = lpeg.P"]]"
local mdendl = lpeg.space^0
local nl = lpeg.P"\r\n"
local ws = lpeg.S" \t" * #(1-nl)

local _ws = (lpeg.space^0)
local _nws = (1 - lpeg.space)^1
local trim = lpeg.Cs((_ws/"") * lpeg.C(((_ws * _nws)^1) + _nws) * (_ws/""))

local reference = ropen * lpeg.C((1-rclosed)^1) * rclosed

local refs = lpeg.Ct(sepby(","*lpeg.space^0, reference))
local function bold(P) return "*" * P * "*" end

local extension_clause = lpeg.Cg(
      exactly(4, hash) 
    * " "
    * "*" * "extends" *" "* refs * "*" 
    , "superclasses"
) * mdendl

local trimmed_content = lpeg.S"\n\r"/"" + (1 - hash)
local description = lpeg.Cg(lpeg.Cs(trimmed_content^0), "description")

local constructor_start= 
      exactly(2, hash) 
    * lpeg.space 
    * "Constructor" 
    * mdendl

local lua_word = ("_" + lpeg.alpha) * ("_" + lpeg.alnum)^0

local proper_noun = lpeg.upper * (lpeg.alnum)^0

local word = lpeg.C(lua_word)

local arg_list = lpeg.Ct(bracket(sepby(','*ws^0, word + lpeg.C"...")^-1))

local constructor = 
      exactly(3, hash) 
    * " " 
    * lpeg.Cg(proper_noun, "class") 
    * lpeg.Cg(arg_list, "constructor")


constructor_clause = constructor_start * constructor * mdendl

local rquote = lpeg.P">"

local function quote(p) return rquote * p end
local function linequote(p) return rquote * p * nl end

local bar = lpeg.P"|"

local table_word = (1 - (lpeg.S"\n\r" + bar))^1

local table_entry = lpeg.C(sepby(ws^1, table_word))
local empty_row = between(bar, (ws ^ 0)*(lpeg.P":"^-1) * lpeg.P"-"^1 * (lpeg.P":"^-1) * ws^0)
local row = between(bar, table_entry)
local filled_row = lpeg.Ct(row)
local rows = lpeg.Ct(sepby(lpeg.space^0, filled_row))
local quoted_rows = lpeg.Ct(sepby(lpeg.space^0 * ">", filled_row))
local argument_header = ">| Parameter | Type | Optional |" + lpeg.P">| Parameter | Type |" 

local argument_table = lpeg.Ct(
      argument_header * lpeg.space^1
    * ">" * empty_row * lpeg.space^1
    * ">" * lpeg.Cg(quoted_rows, "content") * lpeg.space^0
)/ function(args)
    local out = {}
    for _, arg in ipairs(args.content) do 
        out[trim:match(arg[1])] = {trim:match(arg[2]), arg[3] and trim:match(arg[3]) and true or false}
    end
    return out
end


local inherited_prop_start = lpeg.Cg(
    exactly(2, hash) * " " * "Properties Inherited From" * " " * reference, "class"
)*mdendl

local function trimall(t) 
    if type(t) == 'string' then return trim:match(t) or ''
    elseif type(t) ~= 'table' then return t end 
    local new = {} 
    for k ,v in pairs(t) do 
        new[k] = trimall(v)
    end  
return new end

local prop_heading = lpeg.P"| Name | Type | Description |"
local function normalize_property(name, type, desc) 
    return trimall{name = name, type = type, desc = desc} 
end
local function row_to_prop_map(r) 
    for i = 1, #r do 
        local it = r[i]
        r[it.name] = it
        r[i] = nil
    end
    return r
end
local prop_rows = lpeg.Ct(sepby(lpeg.space^0, row/normalize_property))/row_to_prop_map
local prop_tab = 
      prop_heading * mdendl
    * empty_row * mdendl
    * lpeg.Cg(prop_rows, "properties")

local inherited_prop = lpeg.Ct(
      inherited_prop_start
    * prop_tab
)

local inherited_prop_clause = lpeg.Cg(
    lpeg.Ct(sepby(mdendl, inherited_prop)), "inherited_properties"
) * mdendl

local prop_start = exactly(2, hash) * lpeg.space * "Properties" * mdendl

local properties_clause = prop_start * prop_tab * mdendl

local inherited_methods_start = lpeg.Cg(
    exactly(2, hash) * " " * "Methods Inherited From" * " " * reference, "class"
)*mdendl

local to_eol = lpeg.C((1 - nl)^1)

local method_item = lpeg.Ct(
      exactly(3, hash) 
    * " "
    * lpeg.Cg(word, "method")
    * lpeg.Cg(arg_list, "arguments")
    * mdendl
    * optionally(lpeg.Cg(argument_table, "method_arguments"))
    * ">" * mdendl
    * lpeg.Cg(quote(to_eol), "method_description") * mdendl
    * ">" * mdendl
    * quote("Returns: " * lpeg.Cg(to_eol, "returns"))
)/trimall

local function row_to_method_map(r) 
    for i = 1, #r do 
        local it = r[i] 
        r[it.method] = it 
        r[i] = nil
    end
    return r
end
local raw_methods = lpeg.Ct(sepby(mdendl, method_item))/row_to_method_map
local methods = lpeg.Cg(raw_methods, "methods")
local function row_to_inhrm_map(r)
    for i = 1, #r do 
        local it = r[i] 
        r[it.class] = it 
        r[i] = nil
    end
    return r
end

local inherited_method = lpeg.Ct(inherited_methods_start * methods)
local inherited_methods = lpeg.Ct(sepby(mdendl, inherited_method))/row_to_inhrm_map
local inherited_methods_clause = lpeg.Cg(
    inherited_methods, "inherited_methods"
) * mdendl

local methods_start = exactly(2, hash) * lpeg.space * "Methods" *mdendl

local methods_clause = methods_start * methods * mdendl

local static_methods = exactly(2, hash) * lpeg.space * "Static Methods" * mdendl

local static_methods_clause = static_methods * lpeg.Cg(raw_methods, "static_methods") * mdendl

local document = lpeg.Ct(
      optionally(extension_clause)
    * description
    * optionally(constructor_clause * optionally(lpeg.Cg(argument_table, "constructor_arguments")))
    * optionally(inherited_prop_clause)
    * optionally(properties_clause)
    * optionally(static_methods_clause)
    * optionally(inherited_methods_clause)
    * optionally(methods_clause)
    * lpeg.Cg(lpeg.Cp(), "got")
)

return document
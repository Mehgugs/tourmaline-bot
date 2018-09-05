
local lpeg = require("lpeg")
-- Lexical Elements
local Space = lpeg.S(" \n\t")^0
local maybe = function(p) return p^-1 end
local digits = lpeg.R'09'^1
local mpm = maybe(lpeg.S'+-')
local dot = lpeg.P'.'
local exp = lpeg.S'eE'
local float = mpm * digits * maybe(dot*digits) * maybe(exp*mpm*digits)
local Number = lpeg.C(float + lpeg.P("pi") + lpeg.P("π")) * Space
local FactorOp = lpeg.C(lpeg.S("+-")) * Space
local TermOp = lpeg.C(lpeg.S("*/")) * Space
local Open = "(" * Space
local Close = ")" * Space

local lower_letter = lpeg.R("az")
local upper_letter = lpeg.R("AZ")
local digit = lpeg.R("09")
local letter = lower_letter + upper_letter
local alphanum = letter + digit
local alphanum_ = alphanum + lpeg.S("_")
local alpha_ = letter + lpeg.S("_")
local func_pattern = alpha_ * alphanum_^0
local func = lpeg.C(func_pattern) * Space
local param_beg = lpeg.P("(") * Space
local param_end = lpeg.P(")") * Space
local comma = lpeg.P(",") * Space


-- Auxiliary function
local function eval (v1, op, v2)
 if (op == "+") then return v1 + v2
 elseif (op == "-") then return v1 - v2
 elseif (op == "*") then return v1 * v2
 elseif (op == "/") then return v1 / v2
 end
end

local bit = require"bit"

local function tonumberx(n) return (n == 'pi' or n == 'π') and math.pi or tonumber(n) end

local function_table = {
  ["abs"] = function (x) return math.abs(x) end,
  ["pow"] = function (x,y) return x ^ y end,
  ["or"] = bit.bor,
  ["and"] = bit.band,
  ["not"] = bit.bnot,
  ["lshift"] = bit.lshift, 
  ["rshift"] = bit.rshift,
  ["rol"] = bit.rol,
  ["ror"] = bit.ror,
  ["exp"] = function(x) return math.exp(x) end,
  ["ln"] = function(x) return math.log(x) end,
  ["log"] = math.log,
  ["sin"] = math.sin,
  ["cos"] = math.cos,
  ["tan"] = math.tan,
  ["arcsin"] = math.asin,
  ["arccos"] = math.acos,
  ["arctan"] = math.atan,
  ["floor"] = math.floor,
  ["ceil"] = math.ceil,
  sinh= math.sinh, 
  cosh= math.cosh, 
  tanh= math.tanh, 
}

local function evalfunc(f,x)
    local func = function_table[f]
    if func then return func(x)
    else return x
    end
end

-- Grammar
local V = lpeg.V
local G = lpeg.P{ "Exp",
 Exp = lpeg.Cf(V"Factor" * lpeg.Cg(FactorOp * V"Factor")^0, eval);
 Factor = lpeg.Cf(V"Term" * lpeg.Cg(TermOp * V"Term")^0, eval);
 func_E = lpeg.Cf(lpeg.Cg(func) * param_beg * lpeg.Cg(V"Exp") *
             lpeg.Cg(comma * V"Exp")^0 * param_end,  evalfunc);
 Term = Number / tonumberx + Open * V"Exp" * Close + V"func_E";
}

return G
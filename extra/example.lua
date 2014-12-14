-- Example modify function.  The current implementation does not differentiate
-- between requests and responses and depending on proxyspec type has different
-- limitations that are subject to change as the feature is being improved.

function modify(data)
  data = string.gsub(data, "gzip, deflate", "") --for requests
  data = string.gsub(data, "<title>", "<title>TEST") --for responses
  return data
end

-- vim: set et ts=2 sw=2 ft=lua:

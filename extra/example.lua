-- Example modify function.  The current implementation does not differentiate
-- between requests and responses and cannot modify the Content-Length HTTP
-- header yet if the HTTP body size changes as a result of the modifications,
-- so the usefulness of this is currently somewhat limited.

function modify(data)
  data = string.gsub(data, "gzip, deflate", "") --for requests
  data = string.gsub(data, "<title>", "<title>TEST") --for responses
  return data
end

-- vim: set et ts=2 sw=2 ft=lua:

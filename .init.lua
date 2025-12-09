-- Load wallabean API implementation
dofile('/zip/wallabean.lua')

-- Increase max payload size to 1MB
ProgramMaxPayloadSize(1048576)

-- Disable SSL verification for Fetch() calls
ProgramSslFetchVerify(false)
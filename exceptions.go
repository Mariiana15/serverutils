package serverutils

const MsgDatabase = "error in the database"
const MsgMalFormat = "mal format object response"
const MsgUnauthorized = "unauthorized user"
const MsgNotFound = "car not found in the database"
const MsgDataCorrupt = "data corrupt"

const StateOK = "successful"
const StateKO = "error"
const StatePending = "pending"

///
const MsgResponseOk1 = "Operation is complete"

type ResponseOk struct {
	Message string `json:"message"`
}

package serverutils

const msgDatabase = "error in the database"
const msgMalFormat = "mal format object response"
const msgUnauthorized = "unauthorized user"
const msgNotFound = "car not found in the database"
const msgDataCorrupt = "data corrupt"

const stateOK = "successful"
const stateKO = "error"
const statePending = "pending"

///
const msgResponseOk1 = "Operation is complete"

type responseOk struct {
	Message string `json:"message"`
}

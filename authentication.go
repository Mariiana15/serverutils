package serverutils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mariiana15/dbmanager"
	"github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

type UserHQA struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Phone    string `json:"phone"`
}

type UserIntro struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type Todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

type AccessDetails struct {
	AccessUuid string
	UserId     string
}

func CreateToken(userId string, typeToken bool) (*TokenDetails, error) {

	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 20).Unix()
	td.AccessUuid = uuid.NewV4().String()
	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "jdnfksdmfksd") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userId
	atClaims["exp"] = td.AtExpires
	atClaims["create"] = time.Now().Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	var token dbmanager.Token
	token.ExpireAt = td.AtExpires
	token.UserId = userId
	token.Token = td.AccessToken
	token.Insert(true, typeToken)
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf") //this should be in an env file
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userId
	rtClaims["exp"] = td.RtExpires
	rtClaims["create"] = time.Now().Unix()
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	token.ExpireAt = td.RtExpires
	token.Token = td.RefreshToken
	token.Insert(false, typeToken)
	if err != nil {
		return nil, err
	}
	return td, nil

}

func CreateAuth(userid string) error {

	var token dbmanager.Token
	token.UserId = userid
	err := token.GetToken(false)
	if err != nil {
		return err
	}
	return nil
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return token, nil
}

func VerifyTokenWS(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return token, nil
}

func TokenValid(r *http.Request) error {

	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	claims, ok2 := token.Claims.(jwt.MapClaims)
	if ok2 && token.Valid {
		var token_ dbmanager.Token
		token_.UserId = claims["user_id"].(string)
		errAu := token_.GetToken(true)
		if errAu != nil {
			log.Println(errAu)
			return fmt.Errorf("{\"error\": \"%v\"}", MsgUnauthorized)
		}
		stoken := ExtractToken(r)
		if stoken != token_.Token {
			log.Println(stoken)
			log.Println("---")
			log.Println(token_.Token)
			return fmt.Errorf("{\"error\": \"%v\"}", MsgUnauthorized)
		}
	}

	return nil
}

func TokenValidWS(tokenString string) error {

	token, err := VerifyTokenWS(tokenString)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	claims, ok2 := token.Claims.(jwt.MapClaims)
	if ok2 && token.Valid {
		var token_ dbmanager.Token
		token_.UserId = claims["user_id"].(string)
		errAu := token_.GetToken(true)
		if errAu != nil {
			log.Println(errAu)
			return fmt.Errorf("{\"error\": \"%v\"}", MsgUnauthorized)
		}
		if tokenString != token_.Token {
			return fmt.Errorf("{\"error\": \"%v\"}", MsgUnauthorized)
		}
	}

	return nil
}

func ExtractToken(r *http.Request) string {

	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}
func ExtractTokenMetadataWS(tokenString string) (*AccessDetails, error) {
	token, err := VerifyTokenWS(tokenString)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId := claims["user_id"].(string)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	return nil, err
}

func ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := VerifyToken(r)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId := claims["user_id"].(string)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	return nil, err
}

func GetUserHQA(req *http.Request) (dbmanager.Auth, string) {

	var user UserIntro
	var auth dbmanager.Auth
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return auth, fmt.Sprintf("{\"error\": \"%v\"}", err.Error())
	}
	req.Body.Close()
	err = json.Unmarshal([]byte(body), &user)
	if err != nil {
		return auth, fmt.Sprintf("{\"error\": \"%v\"}", err.Error())
	}
	err = auth.GetUserBasic(user.ID, user.Email)
	if err != nil {
		fmt.Println(err)
	}
	if user.Email != auth.User || user.ID != auth.Pass {
		return auth, fmt.Sprintf("{\"error\": \"%v\"}", "Please provide valid login details")
	}

	return auth, ""
}

/*
func FetchAuth(authD *AccessDetails) (uint64, error) {
	userid, err := client.Get(authD.AccessUuid).Result()
	if err != nil {
		log.Println(err)
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

func DeleteAuth(givenUuid string) (int64, error) {
	deleted, err := client.Del(givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}*/

func HandleRefresh(w http.ResponseWriter, r *http.Request) {

	b, err := GetBodyResponse(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "{\"error\": \"%v\"}", MsgMalFormat)
		return
	}
	refreshToken := b["refresh_token"]
	if refreshToken == nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"error\": \"%v\"}", err)
		return
	}
	//verify the token
	token, err := jwt.Parse(refreshToken.(string), func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"error\": \"%v\"}", err)
		return
	}

	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "{\"error\": \"%v\"}", err)
		return
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		_, ok = claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "{\"error\": \"%v\"}", err)
			return
		}

		userId := claims["user_id"].(string)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "{\"error\": \"%v\"}", err)
			return
		}
		//save the tokens metadata to redis
		saveErr := CreateAuth(userId)
		if saveErr != nil {

			log.Println("555")
			log.Println(saveErr)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "{\"error\": \"%v\"}", saveErr.Error())
			return
		}

		//Create new pairs of refresh and access tokens
		ts, createErr := CreateToken(userId, true)
		if createErr != nil {
			log.Println(createErr)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "{\"error\": \"%v\"}", createErr.Error())
			return
		}
		b, _ := json.Marshal(ts)
		w.Write(b)
	} else {

		b, _ := json.Marshal("{\"message\":\"refresh expired\"}")
		w.Write(b)
	}

}

func HandleLogOut(w http.ResponseWriter, r *http.Request) {

	au, err := ExtractTokenMetadata(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "{\"error\": \"%v\"}", MsgUnauthorized)
		return
	}

	var token dbmanager.Token
	token.Id = au.AccessUuid
	deleteErr := token.DeleteToken(true)
	if deleteErr != nil { //if any goes wrong
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "{\"error\": \"%v\"}", MsgUnauthorized)
		return
	}
	fmt.Fprintf(w, "{\"message\": \"%v\"}", "Successfully logged out")
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {

	u, err := GetUserHQA(r)
	if err != "" {
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		fmt.Fprintf(w, err)
		return
	}
	token, err2 := CreateToken(u.Id, false)
	if err2 != nil {
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		fmt.Fprintf(w, "{\"error\": \"%v\"}", err2.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
	byteData, _ := json.Marshal(token)
	w.Write(byteData)
}

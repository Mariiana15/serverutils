package serverutils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func GetBodyResponse(req *http.Request) (map[string]interface{}, error) {

	body, error := ioutil.ReadAll(req.Body)
	if error != nil {
		fmt.Println(error)
	}
	req.Body.Close()
	var result map[string]interface{}
	err := json.Unmarshal([]byte(body), &result)
	return result, err
}

func GetBodyResponseRequest(client *http.Client, r *http.Request) (string, error) {

	respuesta, err := client.Do(r)
	if err != nil {
		return "Error haciendo petición: ", err
	}
	defer respuesta.Body.Close()
	cuerpoRespuesta, err := ioutil.ReadAll(respuesta.Body)
	if err != nil {
		return "Error leyendo respuesta: ", err
	}
	return string(cuerpoRespuesta), nil
}

func Contains(a []string, x string) bool {

	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

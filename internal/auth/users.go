package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

type User struct {
	Role    string `json:"role"`
	Secret  string `json:"secret"`
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
}

type Users struct {
	Boss     User `json:"boss"`
	Manager1 User `json:"manager1"`
	Manager2 User `json:"manager2"`
}

var AppUsers Users

func LoadUsers(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&AppUsers); err != nil {
		return err
	}

	fmt.Println("Users loaded successfully")
	return nil
}

func SaveUsers(path string) error {
	data, err := json.MarshalIndent(AppUsers, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

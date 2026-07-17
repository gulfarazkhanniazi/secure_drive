package auth

import "fmt"

func SetupUsers(usersPath string) error {
	updated := false

	if AppUsers.Boss.Secret == "" {
		secret, _ := GenerateSecret(
			AppUsers.Boss.Account,
			AppUsers.Boss.Issuer,
		)
		AppUsers.Boss.Secret = secret
		updated = true
		fmt.Println("Boss secret initialized")
	}

	if AppUsers.Manager1.Secret == "" {
		secret, _ := GenerateSecret(
			AppUsers.Manager1.Account,
			AppUsers.Manager1.Issuer,
		)
		AppUsers.Manager1.Secret = secret
		updated = true
		fmt.Println("Manager1 secret initialized")
	}

	if AppUsers.Manager2.Secret == "" {
		secret, _ := GenerateSecret(
			AppUsers.Manager2.Account,
			AppUsers.Manager2.Issuer,
		)
		AppUsers.Manager2.Secret = secret
		updated = true
		fmt.Println("Manager2 secret initialized")
	}

	if updated {
		if err := SaveUsers(usersPath); err != nil {
			return err
		}
	}

	return nil
}

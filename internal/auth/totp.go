package auth

import (
	"fmt"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func GenerateSecret(account, issuer string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func VerifyCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

func GenerateOTPURL(secret, account, issuer string) string {
	key, _ := otp.NewKeyFromURL(
		fmt.Sprintf(
			"otpauth://totp/%s:%s?secret=%s&issuer=%s",
			issuer,
			account,
			secret,
			issuer,
		),
	)
	return key.URL()
}

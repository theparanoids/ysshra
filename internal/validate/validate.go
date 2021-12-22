package validate

import "github.com/go-playground/validator/v10"

var validate *validator.Validate

func init() {
	validate = validator.New()
}

// Validate returns a validate instance for config validation.
func Validate() *validator.Validate {
	return validate
}

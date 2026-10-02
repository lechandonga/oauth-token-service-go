package oauth

import (
	"fmt"
	"html"
)

func renderLogin(template, banner string, in AuthorizeInput) string {
	return fmt.Sprintf(template, banner,
		html.EscapeString(in.ClientID),
		html.EscapeString(in.RedirectURI),
		html.EscapeString(in.State),
		html.EscapeString(in.Challenge),
		html.EscapeString(in.Scope),
	)
}

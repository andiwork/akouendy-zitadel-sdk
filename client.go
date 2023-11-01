package auth

import (
	"fmt"
	"log"
	"net/http"

	"github.com/imroc/req/v3"
	http_mw "github.com/zitadel/zitadel-go/v2/pkg/api/middleware/http"
)

type ZitadelClient struct {
	*req.Client
	*http_mw.IntrospectionInterceptor
}
type ZitadelUser struct {
	Email              string      `json:"email,omitempty"`
	EmailVerified      bool        `json:"email_verified,omitempty"`
	FamilyName         string      `json:"family_name,omitempty"`
	GivenName          string      `json:"given_name,omitempty"`
	Locale             string      `json:"locale,omitempty"`
	Name               string      `json:"name,omitempty"`
	PreferredUsername  string      `json:"preferred_username,omitempty"`
	Sub                string      `json:"sub,omitempty"`
	UpdatedAt          int         `json:"updated_at,omitempty"`
	UrnZitadelIamRoles interface{} `json:"urn:zitadel:iam:org:project:roles,omitempty"`
}

func NewZitadelClient(baseUrl string, keyPath string) *ZitadelClient {
	introspection, err := http_mw.NewIntrospectionInterceptor(baseUrl, keyPath)
	if err != nil {
		log.Fatal(err)
	}
	return &ZitadelClient{
		IntrospectionInterceptor: introspection,
		Client: req.C().
			SetBaseURL(baseUrl).
			//SetCommonErrorResult(&ErrorMessage{}).
			EnableDumpEachRequest().
			OnAfterResponse(func(client *req.Client, resp *req.Response) error {
				if resp.Err != nil { // There is an underlying error, e.g. network error or unmarshal error.
					return nil
				}
				/*
					if errMsg, ok := resp.ErrorResult().(*ErrorMessage); ok {
						resp.Err = errMsg // Convert api error into go error
						return nil
					} */
				if !resp.IsSuccessState() {
					// Neither a success response nor a error response, record details to help troubleshooting
					resp.Err = fmt.Errorf("bad status: %s\nraw content:\n%s", resp.Status, resp.Dump())
				}
				return nil
			}),
	}
}

func (c *ZitadelClient) ZitadelAuth(next http.Handler, user *ZitadelUser) http.Handler {
	return c.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.R().
			SetContext(r.Context()).
			SetHeader("Authorization", r.Header.Get("Authorization")).
			SetSuccessResult(&user).
			Get("/oidc/v1/userinfo")
		next.ServeHTTP(w, r)
	})
}

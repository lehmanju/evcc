package connected

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/evcc-io/evcc/server/db/settings"
	"github.com/evcc-io/evcc/util"
	"github.com/evcc-io/evcc/util/oauth"
	"github.com/evcc-io/evcc/util/request"
	"golang.org/x/oauth2"
)

func Oauth2Config(id, secret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     id,
		ClientSecret: secret,
		RedirectURL:  "http://localhost:7070/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://volvoid.eu.volvocars.com/as/authorization.oauth2",
			TokenURL:  "https://volvoid.eu.volvocars.com/as/token.oauth2",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes: []string{
			oidc.ScopeOpenID,
			"conve:vehicle_relation",
			"energy:recharge_status", "energy:battery_charge_level", "energy:electric_range", "energy:estimated_charging_time", "energy:charging_connection_status", "energy:charging_system_status",
		},
	}
}

type Identity struct {
	oauth2.TokenSource
	log     *util.Logger
	oc      *oauth2.Config
	mu      sync.Mutex
	subject string
}

func NewIdentity(log *util.Logger, config *oauth2.Config, token *oauth2.Token) (oauth2.TokenSource, error) {
	// serialise instance handling
	mu.Lock()
	defer mu.Unlock()
	// reuse instance
	subject := "volvo-connected." + strings.ToLower(config.ClientID)
	if instance := getInstance(subject); instance != nil {
		return instance, nil
	}

	v := &Identity{
		subject: subject,
		oc:      config,
		log:     log,
	}

	var tok oauth2.Token
	if err := settings.Json(v.subject, &tok); err == nil {
		token = &tok
	}

	v.TokenSource = oauth.RefreshTokenSource(token, v)

	if tok, err := v.Token(); err == nil {
		token = tok
	} else {
		return nil, err
	}

	if !token.Valid() {
		return nil, errors.New("token expired and could not be refreshed")
	}

	// add instance
	addInstance(v.subject, v)

	return v, nil
}

func (v *Identity) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// refresh token source
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, request.NewClient(v.log))
	token, err := v.oc.TokenSource(ctx, token).Token()
	if err != nil {
		return nil, err
	}

	err = settings.SetJson(v.subject, token)

	return token, err
}

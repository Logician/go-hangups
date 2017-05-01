package hangups

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type Session struct {
	GetAuthToken     func(string, interface{}) string
	GetAuthTokenData interface{}
	RefreshToken     string
	Cookies          string
	Sapisid          string
}

func (s *Session) Init() error {
	oauthConf := &oauth2.Config{
		ClientID:     "936475272427.apps.googleusercontent.com", //iOS id
		ClientSecret: "KWsJlkaMn1jGLxQpWxMnOox-",                //iOS secret
		Scopes: []string{
			"https://www.google.com/accounts/OAuthLogin",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/programmatic_auth", //interactive user login
			TokenURL: "https://accounts.google.com/o/oauth2/token",             //API endpoint to get access token from refresh token or auth code
		},
		// RedirectURL: "urn:ietf:wg:oauth:2.0:oob", //dont redirect - show a page with the auth_code ready to be copied
	}

	client, err := s.getOauthClient(oauthConf)
	if err != nil {
		return err
	}

	err = s.setCookies(client)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) setCookies(client *http.Client) error {
	cookieJar, _ := cookiejar.New(nil)
	client.Jar = cookieJar

	resp, err := client.Get("https://accounts.google.com/accounts/OAuthLogin?source=hangups&issueuberauth=1")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	uberauth, _ := ioutil.ReadAll(resp.Body)

	mergeSessionUrl := fmt.Sprintf("https://accounts.google.com/MergeSession?service=mail&continue=http://www.google.com&uberauth=%s", uberauth)
	// url encode it
	url, _ := url.Parse(mergeSessionUrl)
	q := url.Query()
	url.RawQuery = q.Encode()
	resp, err = client.Get(url.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	u, _ := url.Parse("google.com")
	requiredCookies := map[string]string{"SAPISID": "", "HSID": "", "SSID": "", "APISID": "", "SID": ""}
	cookies := make([]string, 0)
	for _, cookie := range client.Jar.Cookies(u) {
		_, found := requiredCookies[cookie.Name]
		if found {
			cookies = append(cookies, cookie.String())
		}
		if "SAPISID" == cookie.Name {
			s.Sapisid = cookie.Value
		}
	}

	s.Cookies = strings.Join(cookies, "; ")

	return nil
}

func (s *Session) getOauthClient(oauthConf *oauth2.Config) (*http.Client, error) {
	var oauthClient *http.Client
	var token *oauth2.Token
	var err error

	if s.RefreshToken == "" {
		token, err = s.tokenFromAuthCode(oauthConf)
	} else {
		token, err = tokenFromRefreshToken(oauthConf, s.RefreshToken)
	}

	if err != nil {
		return nil, err
	}

	s.RefreshToken = token.RefreshToken
	oauthClient = oauthConf.Client(oauth2.NoContext, token)

	return oauthClient, nil
}

func tokenFromRefreshToken(oauthConf *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	// generate an expired token with the refreshToken and let TokenSource refresh it
	expiredToken := &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Now().Add(-1 * time.Hour)}
	tokenSource := oauthConf.TokenSource(nil, expiredToken)
	return tokenSource.Token()
}

func (s *Session) tokenFromAuthCode(oauthConf *oauth2.Config) (*oauth2.Token, error) {
	// construct url and encode queries properly
	authURL := oauthConf.AuthCodeURL("randomStateString", oauth2.AccessTypeOffline)
	u, _ := url.Parse(authURL)
	q, _ := url.ParseQuery(u.RawQuery)
	q.Del("access_type")
	q.Del("response_type")
	q.Del("state")
	u.RawQuery = q.Encode()

	// Callback to exchange token with a user interactive authorization URL
	authCode := s.GetAuthToken(u.String(), s.GetAuthTokenData)

	// got the auth_code. Exchange it with an access token
	token, err := oauthConf.Exchange(oauth2.NoContext, authCode)
	return token, err
}

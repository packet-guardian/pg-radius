package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/BurntSushi/toml"
)

type RadiusRequest struct {
	Username             RadiusRequestStrType `json:"User-Name"`
	Userpassword         RadiusRequestStrType `json:"User-Password"`
	NASIPAddress         RadiusRequestStrType `json:"NAS-IP-Address"`
	ServiceType          RadiusRequestIntType `json:"Service-Type"`
	CalledStationID      RadiusRequestStrType `json:"Called-Station-Id"`
	CallingStationID     RadiusRequestStrType `json:"Calling-Station-Id"`
	NASPortType          RadiusRequestIntType `json:"NAS-Port-Type"`
	EventTimestamp       RadiusRequestStrType `json:"Event-Timestamp"`
	ConnectInfo          RadiusRequestStrType `json:"Connect-Info"`
	MessageAuthenticator RadiusRequestStrType `json:"Message-Authenticator"`
}

type RadiusRequestStrType struct {
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

type RadiusRequestIntType struct {
	Type  string `json:"type"`
	Value []int  `json:"value"`
}

func (r *RadiusRequest) GetVal(a string) interface{} {
	switch a {
	case "User-Name":
		return r.Username.Value[0]
	case "User-Password":
		return r.Userpassword.Value[0]
	case "NAS-IP-Address":
		return r.NASIPAddress.Value[0]
	case "Service-Type":
		return r.ServiceType.Value[0]
	case "Called-Station-Id":
		return r.CalledStationID.Value[0]
	case "Calling-Station-Id":
		return r.CallingStationID.Value[0]
	case "NAS-Port-Type":
		return r.NASPortType.Value[0]
	case "Event-Timestamp":
		return r.EventTimestamp.Value[0]
	case "Connect-Info":
		return r.ConnectInfo.Value[0]
	case "Message-Authenticator":
		return r.MessageAuthenticator.Value[0]
	}
	return ""
}

type RadiusRespAttribute struct {
	Operation string   `json:"op"`
	Value     []string `json:"value"`
}

type RadiusResponse map[string]*RadiusRespAttribute

type Config struct {
	Server         ServerConfig          `toml:"server"`
	PacketGuardian PacketGuardianConfig  `toml:"packet-guardian"`
	Wlans          map[string]WlanConfig `toml:"wlans"`
}

type ServerConfig struct {
	Port int
}

type PacketGuardianConfig struct {
	Address  string
	Username string
	Password string
}

type WlanConfig struct {
	RadiusAttribute string                `toml:"radius_attribute"`
	Conditions      []WlanConditionConfig `toml:"conditions"`
}

type WlanConditionConfig struct {
	If         string `toml:"if"`
	Innet      string `toml:"innet"`
	Thenok     string `toml:"thenok"`
	Thenreject string `toml:"thenreject"`
}

var (
	configFile string
	dev        bool
	verFlag    bool
	testConfig bool

	version   = ""
	buildTime = ""
	builder   = ""
	goversion = ""
)

func init() {
	flag.StringVar(&configFile, "c", "", "Configuration file path")
	flag.BoolVar(&dev, "d", false, "Run in development mode")
	flag.BoolVar(&testConfig, "t", false, "Test main configuration file")
	flag.BoolVar(&verFlag, "version", false, "Display version information")
	flag.BoolVar(&verFlag, "v", verFlag, "Display version information")
}

func main() {
	flag.Parse()

	if verFlag {
		displayVersionInfo()
		return
	}

	config, err := ReadConfig(configFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	if testConfig {
		return
	}

	StartServer(config)
}

func StartServer(config *Config) {
	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		radiusreq := RadiusRequest{}
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode((&radiusreq)); err != nil {
			log.Print(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		deviceMac, err := net.ParseMAC(radiusreq.CallingStationID.Value[0])
		if err != nil {
			log.Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		device := getDeviceFromPacketGuardian(
			config.PacketGuardian.Address,
			config.PacketGuardian.Username,
			config.PacketGuardian.Password,
			deviceMac,
		)
		if device == nil {
			device = &Device{}
		}

		if device.Blacklisted {
			log.Printf("Rejected blocked device %s\n", device.MAC)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		radresp := ProcessResponse(device, &radiusreq, config.Wlans)
		if radresp == nil {
			log.Printf("Rejected device %s; NAS Address: %s\n", radiusreq.CallingStationID.Value[0], radiusreq.NASIPAddress.Value[0])
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		log.Printf("Accepting device %s\n", radiusreq.CallingStationID.Value[0])
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(radresp)
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Server.Port), nil))
}

func GetWLANName(r *RadiusRequest) string {
	return strings.Split(r.CalledStationID.Value[0], ":")[1]
}

func ProcessResponse(device *Device, r *RadiusRequest, wlans map[string]WlanConfig) RadiusResponse {
	wlanname := GetWLANName(r)
	wlan, exists := wlans[wlanname]
	if !exists {
		return nil
	}

	respvalue := ""

	for _, condition := range wlan.Conditions {
		condResult := ProcessWlanCondition(device, r, &condition)
		if condResult != "" {
			respvalue = condResult
			break
		}
	}

	if respvalue == "" {
		return nil
	}

	log.Printf("Accepting device %s to %s\n", r.CallingStationID.Value[0], respvalue)
	resp := RadiusResponse{}
	resp[wlan.RadiusAttribute] = &RadiusRespAttribute{
		Operation: ":=",
		Value:     []string{respvalue},
	}
	return resp
}

func ProcessWlanCondition(device *Device, r *RadiusRequest, cond *WlanConditionConfig) string {
	if cond.If == "" {
		if device.ID == 0 {
			return cond.Thenreject
		}
		return cond.Thenok
	}

	ifAttribute := cond.If
	condok := false

	if cond.Innet != "" {
		_, network, err := net.ParseCIDR(cond.Innet)
		if err != nil {
			log.Println(err.Error())
			return ""
		}

		val, ok := r.GetVal(ifAttribute).(string)
		if !ok {
			log.Println("innet condition requires string attribute")
			return ""
		}

		attributeIP := net.ParseIP(val)
		if attributeIP == nil {
			log.Println("innet condition requires IP adddress attribute")
		}

		condok = network.Contains(attributeIP)
	}

	if condok {
		if device.ID == 0 {
			return cond.Thenreject
		}
		return cond.Thenok
	}

	return ""
}

type PGResp struct {
	Message string  `json:"message"`
	Data    *Device `json:"data"`
}

type Device struct {
	ID             int    `json:"id"`
	MAC            string `json:"mac"`
	Username       string `json:"username"`
	Description    string `json:"description"`
	RegisteredFrom string `json:"registered_from"`
	Platform       string `json:"platform"`
	Expires        string `json:"expires"`
	DateRegistered string `json:"registered"`
	Blacklisted    bool   `json:"blacklisted"`
	LastSeen       string `json:"last_seen"`
	Flagged        bool   `json:"flagged"`
}

func getDeviceFromPacketGuardian(url, user, pass string, mac net.HardwareAddr) *Device {
	url = fmt.Sprintf("%s/api/device/%s", url, mac.String())
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(user, pass)
	resp, err := (&http.Client{}).Do(req)

	if err != nil {
		log.Print(err.Error())
		return nil
	}
	defer resp.Body.Close()

	device := PGResp{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&device); err != nil {
		log.Print(err.Error())
		return nil
	}

	return device.Data
}

func ReadConfig(configFile string) (conf *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
		}
	}()

	if configFile == "" {
		configFile = "config.toml"
	}

	var con Config
	if _, err := toml.DecodeFile(configFile, &con); err != nil {
		return nil, err
	}

	return &con, nil
}

func displayVersionInfo() {
	fmt.Printf(`Packet Guardian - (C) 2021 The Packet Guardian Authors
Component:   Radius REST API
Version:     %s
Built:       %s
Compiled by: %s
Go version:  %s
`, version, buildTime, builder, goversion)
}

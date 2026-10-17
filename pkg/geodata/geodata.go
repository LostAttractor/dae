/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Modified from https://github.com/v2fly/v2ray-core/blob/42b166760b2ba8d984e514b830fcd44e23728e43/infra/conf/geodata/memconservative

package geodata

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func UnmarshalGeoIp(filepath, code string) (*GeoIP, error) {
	return unmarshalGeodata(filepath, code, "GeoIP", new(GeoIP), new(GeoIPList))
}

func UnmarshalGeoSite(filepath, code string) (*GeoSite, error) {
	return unmarshalGeodata(filepath, code, "GeoSite", new(GeoSite), new(GeoSiteList))
}

func unmarshalGeodata[E interface {
	proto.Message
	GetCountryCode() string
}, L interface {
	proto.Message
	GetEntry() []E
}](filepath, code, kind string, entry E, list L) (E, error) {
	var zero E
	decode := func(data []byte, target proto.Message) error {
		if err := proto.Unmarshal(data, target); err != nil {
			return fmt.Errorf("decode %s entry %q from %q: invalid protobuf data (check file format and download integrity): %w", kind, code, filepath, err)
		}
		return nil
	}
	data, err := Decode(filepath, code)
	switch err {
	case nil:
		if err := decode(data, entry); err != nil {
			return zero, err
		}
		return entry, nil
	case errCodeNotFound:
	case errFailedToReadBytes, errFailedToReadExpectedLenBytes, errInvalidGeodataFile, errInvalidGeodataVarintLength:
		log.WithError(err).WithField("file", filepath).Debug("Reading geodata with the full protobuf decoder")
		data, err = os.ReadFile(filepath)
		if err != nil {
			return zero, err
		}
		if err := decode(data, list); err != nil {
			return zero, err
		}
		for _, entry := range list.GetEntry() {
			if strings.EqualFold(code, entry.GetCountryCode()) {
				return entry, nil
			}
		}
	default:
		return zero, err
	}
	return zero, fmt.Errorf("code %v not found in %v", code, filepath)
}

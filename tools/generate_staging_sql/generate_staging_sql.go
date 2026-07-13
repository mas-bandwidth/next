package main

import (
	"fmt"
	"os"

	"github.com/networknext/next/modules/common"
)

const NumRelays = 1000
const BuyerPublicKeyBase64 = "AzcqXbdP3Txq3rHIjRBS4BfG7OoKV9PAZfB0rY7a+ArdizBzFAd2vQ=="
const RelayPublicKeyBase64 = "1nTj7bQmo8gfIDqG+o//GFsak/g1TRo4hl6XXw1JkyI="
const RelayPrivateKeyBase64 = "cwvK44Pr5aHI3vE3siODS7CUgdPI/l1VwjVZ2FvEyAo="

func main() {

	// generate staging.sql

	fmt.Printf("\nGenerating staging.sql\n")

	file, err := os.Create("schemas/sql/staging.sql")
	if err != nil {
		panic(err)
	}

	defer file.Close()

	header_format := `
INSERT INTO route_shaders(route_shader_name) VALUES('test');

INSERT INTO buyers
(
	buyer_name,
	buyer_code,
	live,
	public_key_base64, 
	route_shader_id
) 
VALUES(
	'Test',
	'test',
	true,
	'%s',
	(select route_shader_id from route_shaders where route_shader_name = 'test')
);

INSERT INTO sellers(seller_name, seller_code) VALUES('Test', 'test');
`

	fmt.Fprintf(file, header_format, BuyerPublicKeyBase64)

	datacenter_format := `
INSERT INTO datacenters(
	datacenter_name, 
	latitude, 
	longitude, 
	seller_id)
VALUES(
	'test.%03d',
	%.2f,
	%.2f,
	(select seller_id from sellers where seller_code = 'test')
);
`

	// IMPORTANT: Seed so the random lat/longs are the same each time you run "next config",
	// otherwise staging.sql churns on every run. It's annoying! NOTE: randomLatitude/Longitude
	// draw from the common package random source, so it must be common.SeedRandom here --
	// the old global rand.Seed never affected them and the output churned anyway.
	common.SeedRandom(0x12345)

	for i := range NumRelays {
		fmt.Fprintf(file, datacenter_format, i, randomLatitude(), randomLongitude())
	}

	relay_format := `
INSERT INTO relays(
	relay_name,
	public_ip,
	public_port,
	public_key_base64,
	private_key_base64,
	datacenter_id)
VALUES(
	'test.%03d',
	'127.0.0.1',
	%d,
	'%s',
	'%s',
	(select datacenter_id from datacenters where datacenter_name = 'test.%03d')
);
`

	for i := range NumRelays {
		fmt.Fprintf(file, relay_format, i, 10000+i, RelayPublicKeyBase64, RelayPrivateKeyBase64, i)
	}

	settings_format := `
INSERT INTO buyer_datacenter_settings VALUES(
	(select buyer_id from buyers where buyer_code = 'test'),
	(select datacenter_id from datacenters where datacenter_name = 'test.%03d'),
	true
);
`

	for i := range NumRelays {
		fmt.Fprintf(file, settings_format, i)
	}

	file.Close()

	fmt.Printf("\n")
}

func randomLatitude() float32 {
	return float32(common.RandomInt(-90, +90))
}

func randomLongitude() float32 {
	return float32(common.RandomInt(-180, +180))
}

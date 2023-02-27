package admin

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Controller struct {
	pgsql *sql.DB
}

func CreateController(config string) *Controller {
	pgsql, err := sql.Open("postgres", config)
	if err != nil {
		panic(fmt.Sprintf("could not connect to postgres: %v", err))
	}
	err = pgsql.Ping()
	if err != nil {
		panic(fmt.Sprintf("could not ping postgres: %v", err))
	}
	fmt.Printf("successfully connected to postgres\n")
	return &Controller{pgsql: pgsql}
}

// -----------------------------------------------------------------------

type CustomerData struct {
	CustomerId   uint64 `json:"customer_id"`
	CustomerName string `json:"customer_name"`
	CustomerCode string `json:"customer_code"`
	Live         bool   `json:"live"`
	Debug        bool   `json:"debug"`
}

func (controller *Controller) CreateCustomer(customerData *CustomerData) (uint64, error) {
	sql := "INSERT INTO customers (customer_name, customer_code, live, debug) VALUES ($1, $2, $3, $4) RETURNING customer_id;"
	result := controller.pgsql.QueryRow(sql, customerData.CustomerName, customerData.CustomerCode, customerData.Live, customerData.Debug)
	customerId := uint64(0)
	if err := result.Scan(&customerId); err != nil {
		return 0, fmt.Errorf("could not insert customer: %v\n", err)
	}
	return customerId, nil
}

func (controller *Controller) ReadCustomers() ([]CustomerData, error) {
	customers := make([]CustomerData, 0)
	rows, err := controller.pgsql.Query("SELECT customer_id, customer_name, customer_code, live, debug FROM customers;")
	if err != nil {
		return nil, fmt.Errorf("could not read customers: %v\n", err)
	}
	defer rows.Close()
	for rows.Next() {
		row := CustomerData{}
		if err := rows.Scan(&row.CustomerId, &row.CustomerName, &row.CustomerCode, &row.Live, &row.Debug); err != nil {
			return nil, fmt.Errorf("could not scan customer row: %v\n", err)
		}
		customers = append(customers, row)
	}
	return customers, nil
}

func (controller *Controller) UpdateCustomer(customerData *CustomerData) error {
	// IMPORTANT: Cannot change customer id once created
	sql := "UPDATE customers SET customer_name = $1, customer_code = $2, live = $3, debug = $4 WHERE customer_id = $5;"
	_, err := controller.pgsql.Exec(sql, customerData.CustomerName, customerData.CustomerCode, customerData.Live, customerData.Debug, customerData.CustomerId)
	return err
}

func (controller *Controller) DeleteCustomer(customerId uint64) error {
	sql := "DELETE FROM customers WHERE customer_id = $1;"
	_, err := controller.pgsql.Exec(sql, customerId)
	return err
}

// -----------------------------------------------------------------------

type RouteShaderData struct {
	RouteShaderId             uint64  `json:"route_shader_id"`
	RouteShaderName           string  `json:"route_shader_name"`
	ABTest                    bool    `json:"ab_test"`
	AcceptableLatency         int     `json:"acceptable_latency"`
	AcceptablePacketLoss      float32 `json:"acceptable_packet_loss"`
	PacketLossSustained       float32 `json:"packet_loss_sustained"`
	AnalysisOnly              bool    `json:"analysis_only"`
	BandwidthEnvelopeUpKbps   int     `json:"bandwidth_envelope_up_kbps"`
	BandwidthEnvelopeDownKbps int     `json:"bandwidth_envelope_down_kbps"`
	DisableNetworkNext        bool    `json:"disable_network_next"`
	LatencyThreshold          int     `json:"latency_threshold"`
	Multipath                 bool    `json:"multipath"`
	ReduceLatency             bool    `json:"reduce_latency"`
	ReducePacketLoss          bool    `json:"reduce_packet_loss"`
	SelectionPercent          float32 `json:"selection_percent"`
	MaxLatencyTradeOff        int     `json:"max_latency_trade_off"`
	MaxNextRTT                int     `json:"max_next_rtt"`
	RouteSwitchThreshold      int     `json:"route_switch_threshold"`
	RouteSelectThreshold      int     `json:"route_select_threshold"`
	RTTVeto_Default           int     `json:"rtt_veto_default"`
	RTTVeto_Multipath         int     `json:"rtt_veto_multipath"`
	RTTVeto_PacketLoss        int     `json:"rtt_veto_packetloss"`
	ForceNext                 bool    `json:"force_next"`
	RouteDiversity            int     `json:"route_diversity"`
}

func (controller *Controller) CreateRouteShader(routeShaderData *RouteShaderData) (uint64, error) {
	sql := `
INSERT INTO route_shaders 
(
	route_shader_name,
	ab_test,
	acceptable_latency,
	acceptable_packet_loss,
	packet_loss_sustained,
	analysis_only,
	bandwidth_envelope_up_kbps,
	bandwidth_envelope_down_kbps,
	disable_network_next,
	latency_threshold,
	multipath,
	reduce_latency,
	reduce_packet_loss,
	selection_percent,
	max_latency_trade_off,
	max_next_rtt,
	route_switch_threshold,
	route_select_threshold,
	rtt_veto_default,
	rtt_veto_multipath,
	rtt_veto_packetloss,
	force_next,
	route_diversity
)
VALUES
(
	$1,
	$2,
	$3,
	$4,
	$5,
	$6,
	$7,
	$8,
	$9,
	$10,
	$11,
	$12,
	$13,
	$14,
	$15,
	$16,
	$17,
	$18,
	$19,
	$20,
	$21,
	$22,
	$23
)
RETURNING route_shader_id;`
	result := controller.pgsql.QueryRow(sql,
		routeShaderData.RouteShaderName,
		routeShaderData.ABTest,
		routeShaderData.AcceptableLatency,
		routeShaderData.AcceptablePacketLoss,
		routeShaderData.PacketLossSustained,
		routeShaderData.AnalysisOnly,
		routeShaderData.BandwidthEnvelopeUpKbps,
		routeShaderData.BandwidthEnvelopeDownKbps,
		routeShaderData.DisableNetworkNext,
		routeShaderData.LatencyThreshold,
		routeShaderData.Multipath,
		routeShaderData.ReduceLatency,
		routeShaderData.ReducePacketLoss,
		routeShaderData.SelectionPercent,
		routeShaderData.MaxLatencyTradeOff,
		routeShaderData.MaxNextRTT,
		routeShaderData.RouteSwitchThreshold,
		routeShaderData.RouteSelectThreshold,
		routeShaderData.RTTVeto_Default,
		routeShaderData.RTTVeto_Multipath,
		routeShaderData.RTTVeto_PacketLoss,
		routeShaderData.ForceNext,
		routeShaderData.RouteDiversity,
	)
	routeShaderId := uint64(0)
	if err := result.Scan(&routeShaderId); err != nil {
		return 0, fmt.Errorf("could not insert route shader: %v\n", err)
	}
	return routeShaderId, nil
}

func (controller *Controller) ReadRouteShaders() ([]RouteShaderData, error) {
	routeShaders := make([]RouteShaderData, 0)
	sql := `
SELECT
	route_shader_id,
	route_shader_name,
	ab_test,
	acceptable_latency,
	acceptable_packet_loss,
	packet_loss_sustained,
	analysis_only,
	bandwidth_envelope_up_kbps,
	bandwidth_envelope_down_kbps,
	disable_network_next,
	latency_threshold,
	multipath,
	reduce_latency,
	reduce_packet_loss,
	selection_percent,
	max_latency_trade_off,
	max_next_rtt,
	route_switch_threshold,
	route_select_threshold,
	rtt_veto_default,
	rtt_veto_multipath,
	rtt_veto_packetloss,
	force_next,
	route_diversity
FROM
	route_shaders;`
	rows, err := controller.pgsql.Query(sql)
	if err != nil {
		return nil, fmt.Errorf("could not read route shaders: %v\n", err)
	}
	defer rows.Close()
	for rows.Next() {
		row := RouteShaderData{}
		err := rows.Scan(
			&row.RouteShaderId,
			&row.RouteShaderName,
			&row.ABTest,
			&row.AcceptableLatency,
			&row.AcceptablePacketLoss,
			&row.PacketLossSustained,
			&row.AnalysisOnly,
			&row.BandwidthEnvelopeUpKbps,
			&row.BandwidthEnvelopeDownKbps,
			&row.DisableNetworkNext,
			&row.LatencyThreshold,
			&row.Multipath,
			&row.ReduceLatency,
			&row.ReducePacketLoss,
			&row.SelectionPercent,
			&row.MaxLatencyTradeOff,
			&row.MaxNextRTT,
			&row.RouteSwitchThreshold,
			&row.RouteSelectThreshold,
			&row.RTTVeto_Default,
			&row.RTTVeto_Multipath,
			&row.RTTVeto_PacketLoss,
			&row.ForceNext,
			&row.RouteDiversity,
		)
		if err != nil {
			return nil, fmt.Errorf("could not scan route shader row: %v\n", err)
		}
		routeShaders = append(routeShaders, row)
	}
	return routeShaders, nil
}

func (controller *Controller) UpdateRouteShader(routeShaderData *RouteShaderData) error {
	// IMPORTANT: Cannot change route shader id once created
	sql := `
UPDATE route_shaders 
SET 
	route_shader_name = $1, 
	ab_test = $2,
	acceptable_latency = $3,
	acceptable_packet_loss = $4,
	packet_loss_sustained = $5,
	analysis_only = $6,
	bandwidth_envelope_up_kbps = $7,
	bandwidth_envelope_down_kbps = $8,
	disable_network_next = $9,
	latency_threshold = $10,
	multipath = $11,
	reduce_latency = $12,
	reduce_packet_loss = $13,
	selection_percent = $14,
	max_latency_trade_off = $15,
	max_next_rtt = $16,
	route_switch_threshold = $17,
	route_select_threshold = $18,
	rtt_veto_default = $19,
	rtt_veto_multipath = $20,
	rtt_veto_packetloss = $21,
	force_next = $22,
	route_diversity = $23
WHERE
	route_shader_id = $24;`
	_, err := controller.pgsql.Exec(sql,
		routeShaderData.RouteShaderName,
		routeShaderData.ABTest,
		routeShaderData.AcceptableLatency,
		routeShaderData.AcceptablePacketLoss,
		routeShaderData.PacketLossSustained,
		routeShaderData.AnalysisOnly,
		routeShaderData.BandwidthEnvelopeUpKbps,
		routeShaderData.BandwidthEnvelopeDownKbps,
		routeShaderData.DisableNetworkNext,
		routeShaderData.LatencyThreshold,
		routeShaderData.Multipath,
		routeShaderData.ReduceLatency,
		routeShaderData.ReducePacketLoss,
		routeShaderData.SelectionPercent,
		routeShaderData.MaxLatencyTradeOff,
		routeShaderData.MaxNextRTT,
		routeShaderData.RouteSwitchThreshold,
		routeShaderData.RouteSelectThreshold,
		routeShaderData.RTTVeto_Default,
		routeShaderData.RTTVeto_Multipath,
		routeShaderData.RTTVeto_PacketLoss,
		routeShaderData.ForceNext,
		routeShaderData.RouteDiversity,
		routeShaderData.RouteShaderId,
	)
	return err
}

func (controller *Controller) DeleteRouteShader(routeShaderId uint64) error {
	sql := "DELETE FROM route_shaders WHERE route_shader_id = $1;"
	_, err := controller.pgsql.Exec(sql, routeShaderId)
	return err
}

// -----------------------------------------------------------------------

type BuyerData struct {
	BuyerId         uint64 `json:"buyer_id"`
	BuyerName       string `json:"buyer_name"`
	PublicKeyBase64 string `json:"public_key_base64"`
	CustomerId      uint64 `json:"customer_id"`
	RouteShaderId   uint64 `json:"route_shader_id"`
}

func (controller *Controller) CreateBuyer(buyerData *BuyerData) (uint64, error) {
	sql := "INSERT INTO buyers (buyer_name, public_key_base64, customer_id, route_shader_id) VALUES ($1, $2, $3, $4) RETURNING buyer_id;"
	result := controller.pgsql.QueryRow(sql, buyerData.BuyerName, buyerData.PublicKeyBase64, buyerData.CustomerId, buyerData.RouteShaderId)
	buyerId := uint64(0)
	if err := result.Scan(&buyerId); err != nil {
		return 0, fmt.Errorf("could not insert buyer: %v\n", err)
	}
	return buyerId, nil
}

func (controller *Controller) ReadBuyers() ([]BuyerData, error) {
	buyers := make([]BuyerData, 0)
	rows, err := controller.pgsql.Query("SELECT buyer_id, buyer_name, public_key_base64, customer_id, route_shader_id FROM buyers;")
	if err != nil {
		return nil, fmt.Errorf("could not read buyers: %v\n", err)
	}
	defer rows.Close()
	for rows.Next() {
		row := BuyerData{}
		if err := rows.Scan(&row.BuyerId, &row.BuyerName, &row.PublicKeyBase64, &row.CustomerId, &row.RouteShaderId); err != nil {
			return nil, fmt.Errorf("could not scan buyer row: %v\n", err)
		}
		buyers = append(buyers, row)
	}
	return buyers, nil
}

func (controller *Controller) UpdateBuyer(buyerData *BuyerData) error {
	// IMPORTANT: Cannot change buyer id once created
	sql := "UPDATE buyers SET buyer_name = $1, public_key_base64 = $2, customer_id = $3, route_shader_id = $4 WHERE buyer_id = $5;"
	_, err := controller.pgsql.Exec(sql, buyerData.BuyerName, buyerData.PublicKeyBase64, buyerData.CustomerId, buyerData.RouteShaderId, buyerData.BuyerId)
	return err
}

func (controller *Controller) DeleteBuyer(buyerId uint64) error {
	sql := "DELETE FROM buyers WHERE buyer_id = $1;"
	_, err := controller.pgsql.Exec(sql, buyerId)
	return err
}

// -----------------------------------------------------------------------

type SellerData struct {
	SellerId   uint64 `json:"seller_id"`
	SellerName string `json:"seller_name"`
	CustomerId uint64 `json:"customer_id"`
}

func (controller *Controller) CreateSeller(sellerData *SellerData) (uint64, error) {
	var result *sql.Row
	if sellerData.CustomerId != 0 {
		sql := "INSERT INTO sellers (seller_name, customer_id) VALUES ($1, $2) RETURNING seller_id;"
		result = controller.pgsql.QueryRow(sql, sellerData.SellerName, sellerData.CustomerId)
	} else {
		sql := "INSERT INTO sellers (seller_name) VALUES ($1) RETURNING seller_id;"
		result = controller.pgsql.QueryRow(sql, sellerData.SellerName)
	}
	sellerId := uint64(0)
	if err := result.Scan(&sellerId); err != nil {
		return 0, fmt.Errorf("could not insert seller: %v\n", err)
	}
	return sellerId, nil
}

func (controller *Controller) ReadSellers() ([]SellerData, error) {
	sellers := make([]SellerData, 0)
	rows, err := controller.pgsql.Query("SELECT seller_id, seller_name, customer_id FROM sellers;")
	if err != nil {
		return nil, fmt.Errorf("could not read sellers: %v\n", err)
	}
	defer rows.Close()
	for rows.Next() {
		row := SellerData{}
		customerId := sql.NullInt64{}
		if err := rows.Scan(&row.SellerId, &row.SellerName, &customerId); err != nil {
			return nil, fmt.Errorf("could not scan seller row: %v\n", err)
		}
		row.CustomerId = uint64(customerId.Int64)
		sellers = append(sellers, row)
	}
	return sellers, nil
}

func (controller *Controller) UpdateSeller(sellerData *SellerData) error {
	// IMPORTANT: Cannot change seller id once created
	var err error
	if sellerData.CustomerId != 0 {
		sql := "UPDATE sellers SET seller_name = $1, customer_id = $2 WHERE seller_id = $3;"
		_, err = controller.pgsql.Exec(sql, sellerData.SellerName, sellerData.CustomerId, sellerData.SellerId)
	} else {
		sql := "UPDATE sellers SET seller_name = $1 WHERE seller_id = $2;"
		_, err = controller.pgsql.Exec(sql, sellerData.SellerName, sellerData.SellerId)
	}
	return err
}

func (controller *Controller) DeleteSeller(sellerId uint64) error {
	sql := "DELETE FROM sellers WHERE seller_id = $1;"
	_, err := controller.pgsql.Exec(sql, sellerId)
	return err
}

// -----------------------------------------------------------------------

type DatacenterData struct {
	DatacenterId   uint64  `json:"datacenter_id"`
	DatacenterName string  `json:"datacenter_name"`
	Latitude       float32 `json:"latitude"`
	Longitude      float32 `json:"longitude"`
	SellerId       uint64  `json:"seller_id"`
	Notes          string  `json:"notes"`
}

func (controller *Controller) CreateDatacenter(datacenterData *DatacenterData) (uint64, error) {
	sql := "INSERT INTO datacenters (datacenter_name, latitude, longitude, seller_id, notes) VALUES ($1, $2, $3, $4, $5) RETURNING datacenter_id;"
	result := controller.pgsql.QueryRow(sql, datacenterData.DatacenterName, datacenterData.Latitude, datacenterData.Longitude, datacenterData.SellerId, datacenterData.Notes)
	datacenterId := uint64(0)
	if err := result.Scan(&datacenterId); err != nil {
		return 0, fmt.Errorf("could not insert datacenter: %v\n", err)
	}
	return datacenterId, nil
}

func (controller *Controller) ReadDatacenters() ([]DatacenterData, error) {
	datacenters := make([]DatacenterData, 0)
	rows, err := controller.pgsql.Query("SELECT datacenter_id, datacenter_name, latitude, longitude, seller_id, notes FROM datacenters;")
	if err != nil {
		return nil, fmt.Errorf("could not read datacenters: %v\n", err)
	}
	defer rows.Close()
	for rows.Next() {
		row := DatacenterData{}
		if err := rows.Scan(&row.DatacenterId, &row.DatacenterName, &row.Latitude, &row.Longitude, &row.SellerId, &row.Notes); err != nil {
			return nil, fmt.Errorf("could not scan datacenter row: %v\n", err)
		}
		datacenters = append(datacenters, row)
	}
	return datacenters, nil
}

func (controller *Controller) UpdateDatacenter(datacenterData *DatacenterData) error {
	// IMPORTANT: Cannot change datacenter id once created
	var err error
	if datacenterData.SellerId != 0 {
		sql := "UPDATE datacenters SET datacenter_name = $1, latitude = $2, longitude = $3, seller_id = $4, notes = $5 WHERE datacenter_id = $6;"
		_, err = controller.pgsql.Exec(sql, datacenterData.DatacenterName, datacenterData.Latitude, datacenterData.Longitude, datacenterData.SellerId, datacenterData.Notes, datacenterData.DatacenterId)
	} else {
		sql := "UPDATE datacenters SET datacenter_name = $1, latitude = $2, longitude = $3, notes = $4 WHERE datacenter_id = $5;"
		_, err = controller.pgsql.Exec(sql, datacenterData.DatacenterName, datacenterData.Latitude, datacenterData.Longitude, datacenterData.Notes, datacenterData.DatacenterId)
	}
	return err
}

func (controller *Controller) DeleteDatacenter(datacenterId uint64) error {
	sql := "DELETE FROM datacenters WHERE datacenter_id = $1;"
	_, err := controller.pgsql.Exec(sql, datacenterId)
	return err
}

// -----------------------------------------------------------------------

type RelayData struct {
	RelayId          uint64 `json:"relay_id"`
	RelayName        string `json:"relay_name"`
	DatacenterId     uint64 `json:"datacenter_id"`
	PublicIP         string `json:"public_ip"`
	PublicPort       int    `json:"public_port"`
	InternalIP       string `json:"internal_ip"`
	InternalPort     int    `json:"internal_port`
	InternalGroup    string `json:"internal_group`
	SSH_IP           string `json:"ssh_ip"`
	SSH_Port         int    `json:"ssh_port`
	SSH_User         string `json:"ssh_user`
	PublicKeyBase64  string `json:"public_key_base64"`
	PrivateKeyBase64 string `json:"private_key_base64"`
	Version          string `json:"version"`
	MRC              int    `json:"mrc"`
	PortSpeed        int    `json:"port_speed"`
	MaxSessions      int    `json:"max_sessions"`
	Notes            string `json:"notes"`
}

func (controller *Controller) CreateRelay(relayData *RelayData) (uint64, error) {
	query := `
INSERT INTO relays 
(
	relay_name,
	datacenter_id,
	public_ip,
	public_port,
	internal_ip,
	internal_port,
	internal_group,
	ssh_ip,
	ssh_port,
	ssh_user,
	public_key_base64,
	private_key_base64,
	version,
	mrc,
	port_speed,
	max_sessions,
	notes
)
VALUES
(
	$1,
	$2,
	$3,
	$4,
	$5,
	$6,
	$7,
	$8,
	$9,
	$10,
	$11,
	$12,
	$13,
	$14,
	$15,
	$16,
	$17
)
RETURNING relay_id;`
	result := controller.pgsql.QueryRow(query,
		relayData.RelayName,
		relayData.DatacenterId,
		relayData.PublicIP,
		relayData.PublicPort,
		relayData.InternalIP,
		relayData.InternalPort,
		relayData.InternalGroup,
		relayData.SSH_IP,
		relayData.SSH_Port,
		relayData.SSH_User,
		relayData.PublicKeyBase64,
		relayData.PrivateKeyBase64,
		relayData.Version,
		relayData.MRC,
		relayData.PortSpeed,
		relayData.MaxSessions,
		relayData.Notes,
	)
	relayId := uint64(0)
	if err := result.Scan(&relayId); err != nil {
		fmt.Printf("error: %v\n", err)
		return 0, fmt.Errorf("could not insert relay: %v\n", err)
	}
	return relayId, nil
}

func (controller *Controller) ReadRelays() ([]RelayData, error) {
	relays := make([]RelayData, 0)
	query := `
SELECT
	relay_id,
	relay_name,
	datacenter_id,
	public_ip,
	public_port,
	internal_ip,
	internal_port,
	internal_group,
	ssh_ip,
	ssh_port,
	ssh_user,
	public_key_base64,
	private_key_base64,
	version,
	mrc,
	port_speed,
	max_sessions,
	notes
FROM
	relays;`
	rows, err := controller.pgsql.Query(query)
	if err != nil {
		return nil, fmt.Errorf("could not read relays: %v\n", err)
	}
	defer rows.Close()
	for rows.Next() {
		row := RelayData{}
		err := rows.Scan(
			&row.RelayId,
			&row.RelayName,
			&row.DatacenterId,
			&row.PublicIP,
			&row.PublicPort,
			&row.InternalIP,
			&row.InternalPort,
			&row.InternalGroup,
			&row.SSH_IP,
			&row.SSH_Port,
			&row.SSH_User,
			&row.PublicKeyBase64,
			&row.PrivateKeyBase64,
			&row.Version,
			&row.MRC,
			&row.PortSpeed,
			&row.MaxSessions,
			&row.Notes,
		)
		if err != nil {
			return nil, fmt.Errorf("could not scan relay row: %v\n", err)
		}
		relays = append(relays, row)
	}
	return relays, nil
}

func (controller *Controller) UpdateRelay(relayData *RelayData) error {
	// IMPORTANT: Cannot change relay id once created
	sql := `
UPDATE relays 
SET 
	relay_name = $1, 
	datacenter_id = $2,
	public_ip = $3,
	public_port = $4,
	internal_ip = $5,
	internal_port = $6,
	internal_group = $7,
	ssh_ip = $8,
	ssh_port = $9,
	ssh_user = $10,
	public_key_base64 = $11,
	private_key_base64 = $12,
	version = $13,
	mrc = $14,
	port_speed = $15,
	max_sessions = $16,
	notes = $17
WHERE
	relay_id = $18;`
	_, err := controller.pgsql.Exec(sql,
		relayData.RelayName,
		relayData.DatacenterId,
		relayData.PublicIP,
		relayData.PublicPort,
		relayData.InternalIP,
		relayData.InternalPort,
		relayData.InternalGroup,
		relayData.SSH_IP,
		relayData.SSH_Port,
		relayData.SSH_User,
		relayData.PublicKeyBase64,
		relayData.PrivateKeyBase64,
		relayData.Version,
		relayData.MRC,
		relayData.PortSpeed,
		relayData.MaxSessions,
		relayData.Notes,
		relayData.RelayId,
	)
	return err
}

func (controller *Controller) DeleteRelay(relayId uint64) error {
	sql := "DELETE FROM relays WHERE relay_id = $1;"
	_, err := controller.pgsql.Exec(sql, relayId)
	return err
}

// -----------------------------------------------------------------------

type BuyerDatacenterSettings struct {
	BuyerId            uint64 `json:"buyer_id"`
	DatacenterId       uint64 `json:"datacenter_id"`
	EnableAcceleration bool   `json:"enable_acceleration"`
}

func (controller *Controller) CreateBuyerDatacenterSettings(settings *BuyerDatacenterSettings) error {
	sql := "INSERT INTO buyer_datacenter_settings (buyer_id, datacenter_id, enable_acceleration) VALUES ($1, $2, $3);"
	_, err := controller.pgsql.Exec(sql, settings.DatacenterId, settings.BuyerId, settings.EnableAcceleration)
	return err
}

func (controller *Controller) ReadBuyerDatacenterSettings() ([]BuyerDatacenterSettings, error) {
	settings := make([]BuyerDatacenterSettings, 0)
	rows, err := controller.pgsql.Query("SELECT buyer_id, datacenter_id, enable_acceleration FROM buyer_datacenter_settings;")
	if err != nil {
		return nil, fmt.Errorf("could not read buyer datacenter settings: %v\n", err)
	}
	defer rows.Close()
	for rows.Next() {
		row := BuyerDatacenterSettings{}
		if err := rows.Scan(&row.BuyerId, &row.DatacenterId, &row.EnableAcceleration); err != nil {
			return nil, fmt.Errorf("could not scan buyer datacenter settings row: %v\n", err)
		}
		settings = append(settings, row)
	}
	return settings, nil
}

func (controller *Controller) UpdateBuyerDatacenterSettings(settings *BuyerDatacenterSettings) error {
	// IMPORTANT: Cannot change buyer id or datacenter id once created
	sql := "UPDATE buyer_datacenter_settings SET enable_acceleration = $1 WHERE buyer_id = $2, datacenter_id = $3;"
	_, err := controller.pgsql.Exec(sql, settings.EnableAcceleration, settings.BuyerId, settings.DatacenterId)
	return err
}

func (controller *Controller) DeleteBuyerDatacenterSettings(buyerId uint64, datacenterId uint64) error {
	sql := "DELETE FROM buyer_datacenter_settings WHERE relay_id = $1, datacenter_id = $2;"
	_, err := controller.pgsql.Exec(sql, buyerId, datacenterId)
	return err
}

// -----------------------------------------------------------------------

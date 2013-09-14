//----------------------------------------------------------------------------
// user_logic.v - module
//----------------------------------------------------------------------------
//
// ***************************************************************************
// ** Copyright (c) 1995-2012 Xilinx, Inc.  All rights reserved.            **
// **                                                                       **
// ** Xilinx, Inc.                                                          **
// ** XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS"         **
// ** AS A COURTESY TO YOU, SOLELY FOR USE IN DEVELOPING PROGRAMS AND       **
// ** SOLUTIONS FOR XILINX DEVICES.  BY PROVIDING THIS DESIGN, CODE,        **
// ** OR INFORMATION AS ONE POSSIBLE IMPLEMENTATION OF THIS FEATURE,        **
// ** APPLICATION OR STANDARD, XILINX IS MAKING NO REPRESENTATION           **
// ** THAT THIS IMPLEMENTATION IS FREE FROM ANY CLAIMS OF INFRINGEMENT,     **
// ** AND YOU ARE RESPONSIBLE FOR OBTAINING ANY RIGHTS YOU MAY REQUIRE      **
// ** FOR YOUR IMPLEMENTATION.  XILINX EXPRESSLY DISCLAIMS ANY              **
// ** WARRANTY WHATSOEVER WITH RESPECT TO THE ADEQUACY OF THE               **
// ** IMPLEMENTATION, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OR        **
// ** REPRESENTATIONS THAT THIS IMPLEMENTATION IS FREE FROM CLAIMS OF       **
// ** INFRINGEMENT, IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS       **
// ** FOR A PARTICULAR PURPOSE.                                             **
// **                                                                       **
// ***************************************************************************
//
// ***************************************************************************
// ** User logic software is Copyright (c) 2013 Katja Malvoni 
// ** <kmalvoni at gmail dot com> and it is hereby released to the general 
// ** public under the following terms: Redistribution and use in source and 
// ** binary forms, with or without modification, are permitted.
// ***************************************************************************
//
//----------------------------------------------------------------------------
// Filename:          user_logic.v
// Version:           1.00.a
// Description:       User logic module.
// Date:              Thu Sep  5 14:28:10 2013 (by Create and Import Peripheral Wizard)
// Verilog Standard:  Verilog-2001
//----------------------------------------------------------------------------
// Naming Conventions:
//   active low signals:                    "*_n"
//   clock signals:                         "clk", "clk_div#", "clk_#x"
//   reset signals:                         "rst", "rst_n"
//   generics:                              "C_*"
//   user defined types:                    "*_TYPE"
//   state machine next state:              "*_ns"
//   state machine current state:           "*_cs"
//   combinatorial signals:                 "*_com"
//   pipelined or register delay signals:   "*_d#"
//   counter signals:                       "*cnt*"
//   clock enable signals:                  "*_ce"
//   internal version of output port:       "*_i"
//   device pins:                           "*_pin"
//   ports:                                 "- Names begin with Uppercase"
//   processes:                             "*_PROCESS"
//   component instantiations:              "<ENTITY_>I_<#|FUNC>"
//----------------------------------------------------------------------------

`uselib lib=unisims_ver
`uselib lib=proc_common_v3_00_a

module user_logic
(
  // -- ADD USER PORTS BELOW THIS LINE ---------------
  BRAM_Rst_A,
  BRAM_Clk_A,
  BRAM_En_A,
  BRAM_WE_A,
  BRAM_Addr_A,
  BRAM_WrData_A,
  BRAM_RdData_A, 
  // -- ADD USER PORTS ABOVE THIS LINE ---------------

  // -- DO NOT EDIT BELOW THIS LINE ------------------
  // -- Bus protocol ports, do not add to or delete 
  Bus2IP_Clk,                     // Bus to IP clock
  Bus2IP_Resetn,                  // Bus to IP reset
  Bus2IP_Data,                    // Bus to IP data bus
  Bus2IP_BE,                      // Bus to IP byte enables
  Bus2IP_RdCE,                    // Bus to IP read chip enable
  Bus2IP_WrCE,                    // Bus to IP write chip enable
  IP2Bus_Data,                    // IP to Bus data bus
  IP2Bus_RdAck,                   // IP to Bus read transfer acknowledgement
  IP2Bus_WrAck,                   // IP to Bus write transfer acknowledgement
  IP2Bus_Error,                   // IP to Bus error response
  ip2bus_mstrd_req,               // IP to Bus master read request
  ip2bus_mstwr_req,               // IP to Bus master write request
  ip2bus_mst_addr,                // IP to Bus master read/write address
  ip2bus_mst_be,                  // IP to Bus byte enable
  ip2bus_mst_length,              // Ip to Bus master transfer length
  ip2bus_mst_type,                // Ip to Bus burst assertion control
  ip2bus_mst_lock,                // Ip to Bus bus lock
  ip2bus_mst_reset,               // Ip to Bus master reset
  bus2ip_mst_cmdack,              // Bus to Ip master command ack
  bus2ip_mst_cmplt,               // Bus to Ip master trans complete
  bus2ip_mst_error,               // Bus to Ip master error
  bus2ip_mst_rearbitrate,         // Bus to Ip master re-arbitrate for bus ownership
  bus2ip_mst_cmd_timeout,         // Bus to Ip master command time out
  bus2ip_mstrd_d,                 // Bus to Ip master read data
  bus2ip_mstrd_rem,               // Bus to Ip master read data rem
  bus2ip_mstrd_sof_n,             // Bus to Ip master read start of frame
  bus2ip_mstrd_eof_n,             // Bus to Ip master read end of frame
  bus2ip_mstrd_src_rdy_n,         // Bus to Ip master read source ready
  bus2ip_mstrd_src_dsc_n,         // Bus to Ip master read source dsc
  ip2bus_mstrd_dst_rdy_n,         // Ip to Bus master read dest. ready
  ip2bus_mstrd_dst_dsc_n,         // Ip to Bus master read dest. dsc
  ip2bus_mstwr_d,                 // Ip to Bus master write data
  ip2bus_mstwr_rem,               // Ip to Bus master write data rem
  ip2bus_mstwr_src_rdy_n,         // Ip to Bus master write source ready
  ip2bus_mstwr_src_dsc_n,         // Ip to Bus master write source dsc
  ip2bus_mstwr_sof_n,             // Ip to Bus master write start of frame
  ip2bus_mstwr_eof_n,             // Ip to Bus master write end of frame
  bus2ip_mstwr_dst_rdy_n,         // Bus to Ip master write dest. ready
  bus2ip_mstwr_dst_dsc_n          // Bus to Ip master write dest. ready
  // -- DO NOT EDIT ABOVE THIS LINE ------------------
); // user_logic

// -- ADD USER PARAMETERS BELOW THIS LINE ------------
parameter INIT			= 4'b0000;
parameter P_XOR_EXP		= 4'b0001;
parameter ENCRYPT_INIT		= 4'b0010;
parameter FEISTEL		= 4'b0011;
parameter STORE_L_R		= 4'b0100;
parameter P_XOR_SALT		= 4'b0101;
parameter LOOP			= 4'b0110;
parameter DONE			= 4'b0111;
parameter SET			= 4'b1000;
parameter LOAD_P		= 4'b1001;	
parameter LOAD_EXP_KEY		= 4'b1010;
parameter LOAD_SALT		= 4'b1011;
parameter LOAD_S		= 4'b1100;
parameter UPDATE_L_R		= 4'b1101;
	
parameter P_ARRAY		= 32'b0000000000000100;
parameter P_S0			= 32'b0000000001001100; 
parameter P_S1			= 32'b0000010001001100; 
parameter P_S2			= 32'b0000100001001100; 
parameter P_S3			= 32'b0000110001001100; 
parameter P_EXP_KEY		= 32'b0001000001001100;
parameter P_SALT		= 32'b0001000010010100;
// -- ADD USER PARAMETERS ABOVE THIS LINE ------------

// -- DO NOT EDIT BELOW THIS LINE --------------------
// -- Bus protocol parameters, do not add to or delete
parameter C_MST_NATIVE_DATA_WIDTH        = 32;
parameter C_LENGTH_WIDTH                 = 12;
parameter C_MST_AWIDTH                   = 32;
parameter C_NUM_REG                      = 6;
parameter C_SLV_DWIDTH                   = 32;
// -- DO NOT EDIT ABOVE THIS LINE --------------------

// -- ADD USER PORTS BELOW THIS LINE -----------------
output                               BRAM_Rst_A;
output                               BRAM_Clk_A;
output                               BRAM_En_A;
output     [C_SLV_DWIDTH/8 - 1 : 0]  BRAM_WE_A;
output     [C_MST_AWIDTH - 1 : 0]    BRAM_Addr_A;
output     [C_SLV_DWIDTH - 1 : 0]    BRAM_WrData_A;
input      [C_SLV_DWIDTH - 1 : 0]    BRAM_RdData_A;
// -- ADD USER PORTS ABOVE THIS LINE -----------------

// -- DO NOT EDIT BELOW THIS LINE --------------------
// -- Bus protocol ports, do not add to or delete
input                                     Bus2IP_Clk;
input                                     Bus2IP_Resetn;
input      [C_SLV_DWIDTH-1 : 0]           Bus2IP_Data;
input      [C_SLV_DWIDTH/8-1 : 0]         Bus2IP_BE;
input      [C_NUM_REG-1 : 0]              Bus2IP_RdCE;
input      [C_NUM_REG-1 : 0]              Bus2IP_WrCE;
output     [C_SLV_DWIDTH-1 : 0]           IP2Bus_Data;
output                                    IP2Bus_RdAck;
output                                    IP2Bus_WrAck;
output                                    IP2Bus_Error;
output                                    ip2bus_mstrd_req;
output                                    ip2bus_mstwr_req;
output     [C_MST_AWIDTH-1 : 0]           ip2bus_mst_addr;
output     [(C_MST_NATIVE_DATA_WIDTH/8)-1 : 0] ip2bus_mst_be;
output     [C_LENGTH_WIDTH-1 : 0]         ip2bus_mst_length;
output                                    ip2bus_mst_type;
output                                    ip2bus_mst_lock;
output                                    ip2bus_mst_reset;
input                                     bus2ip_mst_cmdack;
input                                     bus2ip_mst_cmplt;
input                                     bus2ip_mst_error;
input                                     bus2ip_mst_rearbitrate;
input                                     bus2ip_mst_cmd_timeout;
input      [C_MST_NATIVE_DATA_WIDTH-1 : 0] bus2ip_mstrd_d;
input      [(C_MST_NATIVE_DATA_WIDTH)/8-1 : 0] bus2ip_mstrd_rem;
input                                     bus2ip_mstrd_sof_n;
input                                     bus2ip_mstrd_eof_n;
input                                     bus2ip_mstrd_src_rdy_n;
input                                     bus2ip_mstrd_src_dsc_n;
output                                    ip2bus_mstrd_dst_rdy_n;
output                                    ip2bus_mstrd_dst_dsc_n;
output     [C_MST_NATIVE_DATA_WIDTH-1 : 0] ip2bus_mstwr_d;
output     [(C_MST_NATIVE_DATA_WIDTH)/8-1 : 0] ip2bus_mstwr_rem;
output                                    ip2bus_mstwr_src_rdy_n;
output                                    ip2bus_mstwr_src_dsc_n;
output                                    ip2bus_mstwr_sof_n;
output                                    ip2bus_mstwr_eof_n;
input                                     bus2ip_mstwr_dst_rdy_n;
input                                     bus2ip_mstwr_dst_dsc_n;
// -- DO NOT EDIT ABOVE THIS LINE --------------------

//----------------------------------------------------------------------------
// Implementation
//----------------------------------------------------------------------------

  // --USER nets declarations added here, as needed for user logic  
  integer i = 0;
  reg [C_SLV_DWIDTH-1 : 0] done = 0;
  reg [4:0] rounds = 5;
  
  reg [6:0] P_index = 0;
  reg [6:0] EXP_KEY_index = 0;
  reg [4:0] SALT_index = 0;
  reg [2:0] TMP_index = 0;
  reg [4:0] ROUND_index = 0;
  reg [31:0] ptr = 0;
  reg tmp_cnt = 0;
  reg first_or_second = 0;
  reg [2:0] mem_delay = 0;
  	
  reg [31:0] count = 0;
  reg [31:0] L = 0;
  reg [31:0] R = 0;
  reg [3:0] state = 0;
  reg [3:0] substate1 = 0;
  reg [3:0] substate2 = 0;
  reg [31:0] P [17:0];
  reg [31:0] exp_key [17:0];
  reg [31:0] salt [3:0];
  reg [31:0] tmp [3:0];
  		
  reg en;
  reg [3:0] we;
  reg [31:0] addr;
  reg [31:0] din;
  // Nets for user logic slave model s/w accessible register example
  reg        [C_SLV_DWIDTH-1 : 0]           slv_reg0;
  reg        [C_SLV_DWIDTH-1 : 0]           slv_reg1;
  wire       [1 : 0]                        slv_reg_write_sel;
  wire       [1 : 0]                        slv_reg_read_sel;
  reg        [C_SLV_DWIDTH-1 : 0]           slv_ip2bus_data;
  wire                                      slv_read_ack;
  wire                                      slv_write_ack;
  integer                                   byte_index, bit_index;


  wire                                       Bus2IP_Clk;
  wire                                       Bus2IP_Resetn;
  wire      [C_SLV_DWIDTH-1 : 0]             Bus2IP_Data;
  wire      [C_SLV_DWIDTH/8-1 : 0]           Bus2IP_BE;
  wire      [C_NUM_REG-1 : 0]                Bus2IP_RdCE;
  wire      [C_NUM_REG-1 : 0]                Bus2IP_WrCE;
  wire      [C_SLV_DWIDTH-1 : 0]             IP2Bus_Data;
  wire                                       IP2Bus_RdAck;
  wire                                       IP2Bus_WrAck;
  wire                                       IP2Bus_Error;
  wire                                       ip2bus_mstrd_req;
  wire                                       ip2bus_mstwr_req;
  wire     [C_MST_AWIDTH-1 : 0]              ip2bus_mst_addr;
  wire     [(C_MST_NATIVE_DATA_WIDTH/8)-1:0] ip2bus_mst_be;
  wire     [C_LENGTH_WIDTH-1 : 0]        ip2bus_mst_length;
  wire                                       ip2bus_mst_type;
  wire                                       ip2bus_mst_lock;
  wire                                       ip2bus_mst_reset;
  wire                                       bus2ip_mst_cmdack;
  wire                                       bus2ip_mst_cmplt;
  wire                                       bus2ip_mst_error;
  wire                                       bus2ip_mst_rearbitrate;
  wire                                       bus2ip_mst_cmd_timeout;
  wire     [C_MST_NATIVE_DATA_WIDTH-1 : 0]   bus2ip_mstrd_d;
  wire     [(C_MST_NATIVE_DATA_WIDTH/8)-1:0] bus2ip_mstrd_rem; 
  wire                                       bus2ip_mstrd_sof_n;
  wire                                       bus2ip_mstrd_eof_n;
  wire                                       bus2ip_mstrd_src_rdy_n;
  wire                                       bus2ip_mstrd_src_dsc_n;
  wire                                       ip2bus_mstrd_dst_rdy_n;
  wire                                       ip2bus_mstrd_dst_dsc_n;
  wire     [C_MST_NATIVE_DATA_WIDTH-1 : 0]   ip2bus_mstwr_d;
  wire     [(C_MST_NATIVE_DATA_WIDTH/8)-1:0] ip2bus_mstwr_rem;
  wire                                       ip2bus_mstwr_src_rdy_n;
  wire                                       ip2bus_mstwr_src_dsc_n;
  wire                                       ip2bus_mstwr_sof_n;
  wire                                       ip2bus_mstwr_eof_n;
  wire                                       bus2ip_mstwr_dst_rdy_n;
  wire                                       bus2ip_mstwr_dst_dsc_n;

// signals for master model control/status registers write/read
  reg        [C_SLV_DWIDTH-1 : 0]            mst_ip2bus_data;
 wire                                       mst_reg_write_req;
 wire                                       mst_reg_read_req;
 wire       [3 : 0]                         mst_reg_write_sel;
 wire       [3 : 0]                         mst_reg_read_sel;
 wire                                       mst_write_ack;
 wire                                       mst_read_ack;
// signals for master model control/status registers
 reg        [7 : 0]                         mst_reg [0 : 15];
 reg        [15 : 0]                        mst_byte_we;
 wire                                       mst_cntl_rd_req;
 wire                                       mst_cntl_wr_req;
 wire                                       mst_cntl_bus_lock;
 wire                                       mst_cntl_burst;
 wire       [C_MST_AWIDTH-1 : 0]            mst_ip2bus_addr;
 wire       [C_LENGTH_WIDTH-1 : 0]      mst_xfer_length;
 wire       [19 : 0]                    mst_xfer_reg_len;
 wire       [15 : 0]                        mst_ip2bus_be;
 reg                                        mst_go;
// signals for master model command interface state machine
 parameter  [1 : 0]                         CMD_IDLE = 2'b00,
                                            CMD_RUN  = 2'b01,
                                            CMD_WAIT_FOR_DATA  = 2'b10,
                                            CMD_DONE  = 2'b11;
 reg        [1 : 0]                         mst_cmd_sm_state;
 reg                                        mst_cmd_sm_set_done;
 reg                                        mst_cmd_sm_set_error;
 reg                                        mst_cmd_sm_set_timeout;
 reg                                        mst_cmd_sm_busy;
 reg                                        mst_cmd_sm_clr_go;
 reg                                        mst_cmd_sm_rd_req;
 reg                                        mst_cmd_sm_wr_req;
 reg                                        mst_cmd_sm_reset;
 reg                                        mst_cmd_sm_bus_lock;
 reg        [C_MST_AWIDTH-1 : 0]            mst_cmd_sm_ip2bus_addr;
 reg        [(C_MST_NATIVE_DATA_WIDTH/8)-1 : 0]mst_cmd_sm_ip2bus_be;
 reg                                        mst_cmd_sm_xfer_type;
 reg        [C_LENGTH_WIDTH-1 : 0]      mst_cmd_sm_xfer_length;
 reg                                        mst_cmd_sm_start_rd_llink;
 reg                                        mst_cmd_sm_start_wr_llink;
 
// signals for master model read locallink interface state machine
 parameter                                  LLRD_IDLE = 1'b0,
                                            LLRD_GO = 1'b1;
 reg                                        mst_llrd_sm_state;
 reg                                        mst_llrd_sm_dst_rdy;
// signals for master model write locallink interface state machine
 parameter   [2 : 0]                        LLWR_IDLE = 3'b000, 
                                            LLWR_SNGL_INIT = 3'b001, 
                             LLWR_SNGL = 3'b010, 
                             LLWR_BRST_INIT = 3'b011, 
                             LLWR_BRST = 3'b100, 
                             LLWR_BRST_LAST_BEAT = 3'b101;
 
 reg         [2 : 0]                        mst_llwr_sm_state;
 reg                                        mst_llwr_sm_src_rdy;
 reg                                        mst_llwr_sm_sof;
 reg                                        mst_llwr_sm_eof;
 integer                                    mst_llwr_byte_cnt;
 wire                                       mst_fifo_valid_write_xfer;
 wire                                       mst_fifo_valid_read_xfer;
 wire                                       bus2ip_Reset;
 
 parameter                                  BE_WIDTH = C_SLV_DWIDTH/8;
 parameter                                  BYTES_PER_BEAT = C_MST_NATIVE_DATA_WIDTH/8;
 parameter  [7:0]                           GO_DATA_KEY = 8'ha;
 parameter                                  GO_BYTE_LANE = 15;
 
  // --USER logic implementation added here 
   
	assign BRAM_Clk_A = Bus2IP_Clk;
	assign BRAM_En_A = 1'b1;
	assign BRAM_Rst_A = 1'b0;
	assign BRAM_WE_A = we;
	assign BRAM_WrData_A = din;
	assign BRAM_Addr_A = addr;
  
	always @ (posedge Bus2IP_Clk)
	begin
		if(slv_reg0 == 0) begin
			we <= 4'b0000;
			en <= 0;
			count <= 0;
			state <= INIT;
			substate1 <= SET;
			done <= 0;
		end
		else if(slv_reg0 != 0) begin
			if(state == INIT) begin
				if(substate1 == SET) begin
					count <= 'd32;
					substate1 <= LOAD_EXP_KEY;
					en <= 1;
				end
				else if(substate1 == LOAD_EXP_KEY) begin
					if(EXP_KEY_index < 5'd18) begin
						if(mem_delay < 3'd2) begin
							addr <= P_EXP_KEY + EXP_KEY_index * 4;
							mem_delay <= mem_delay + 1;
						end
						else begin
							exp_key[EXP_KEY_index] <= BRAM_RdData_A;
							EXP_KEY_index <= EXP_KEY_index + 5'd1;
							mem_delay <= 0;
						end
					end
					else begin
						EXP_KEY_index <= 5'd0;
						mem_delay <= 0;
						substate1 <=  LOAD_SALT;
					end
				end
				else if(substate1 == LOAD_SALT) begin
					if(SALT_index < 3'd4) begin
						if(mem_delay < 3'd2) begin
							addr <= P_SALT + SALT_index * 4;
							mem_delay <= mem_delay + 3'd1;
						end
						else begin
							salt[SALT_index] <= BRAM_RdData_A;
							SALT_index <= SALT_index + 3'd1;
							mem_delay <= 3'd0;
						end
					end
					else begin
						SALT_index <= 0;
						mem_delay <= 0;
						substate1 <= LOAD_P;
					end
				end							
				else if(substate1 == LOAD_P) begin
					if(P_index < 5'd18) begin
						if(mem_delay < 3'd2) begin
							addr <= P_ARRAY + P_index * 4;
							mem_delay <= mem_delay + 3'd1;
						end
						else begin
							P[P_index] <= BRAM_RdData_A;
							P_index <= P_index + 5'd1;
							mem_delay <= 3'd0;
						end
					end
					else begin
						P_index <= 5'd0;
						mem_delay <= 3'd0;
						state <=  P_XOR_EXP;
						we <= 4'b1111;
					end
				end
			end
			else if(state == P_XOR_EXP) begin
				if(P_index < 5'd18) begin
					we <= 4'b1111;
					addr <= P_ARRAY + P_index * 'd4;
					din <= P[P_index] ^ exp_key[P_index];;
					P_index <= P_index + 5'd1;
					P[P_index] <= P[P_index] ^ exp_key[P_index];
				end
				else begin
					P_index <= 5'd0;
					L <= 0;
					R <= 0;
					state <= ENCRYPT_INIT;
					we <= 4'b0000;
					ptr <= 1;
				end
			end
			else if(state == ENCRYPT_INIT) begin
				if(P_index < 5'd18 && ptr < 5'd20) begin
					if(mem_delay < 3'd2) begin
						we <= 4'b0000;
						addr <= P_ARRAY + P_index * 4;
						mem_delay <= mem_delay + 3'd1;
					end
					else begin
						P[P_index] <= BRAM_RdData_A;
						P_index <= P_index + 5'd1;
						mem_delay <= 0;
					end
				end
				else begin
					P_index <= 5'd0;
					mem_delay <= 3'd0;
					L <= L ^ P[0];
					state <= FEISTEL;
					substate2 <= LOAD_S;
				end
			end
			else if(state == FEISTEL) begin
				if(ROUND_index < 16) begin
					if(substate2 == LOAD_S) begin
						if(TMP_index == 'd3) begin
							if(mem_delay < 3'd2) begin
								we <= 4'b0000;
								addr <= P_S0 + L[31:24] * 'd4;
								mem_delay <= mem_delay + 3'd1;
							end
							else begin
								tmp[TMP_index] <= BRAM_RdData_A;
								TMP_index <= TMP_index - 2'd1;
								mem_delay <= 3'd0;
							end
						 end
						 else if(TMP_index == 'd2) begin
						 	if(mem_delay < 3'd2) begin
						 		we <= 4'b0000;
						 		addr <= P_S1 + L[23:16] * 'd4;
								mem_delay <= mem_delay + 3'd1;
							end
							else begin
								tmp[TMP_index] <= BRAM_RdData_A;
								TMP_index <= TMP_index - 2'd1;
								mem_delay <= 3'd0;
							end
						end
						else if(TMP_index == 'd1) begin
							if(mem_delay < 3'd2) begin
								we <= 4'b0000;
								addr <= P_S2 + L[15:8] * 'd4;
								mem_delay <= mem_delay + 3'd1;
							end
							else begin
								tmp[TMP_index] <= BRAM_RdData_A;
								TMP_index <= TMP_index - 2'd1;
								tmp[2] <= tmp[2] + tmp[3];
								mem_delay <= 3'd0;
							end
						end
						else if(TMP_index == 'd0) begin
							if(mem_delay < 3'd2) begin
								we <= 4'b0000;
								addr <= P_S3 + L[7:0] * 'd4;
								mem_delay <= mem_delay + 3'd1;
							end
							else begin
								tmp[TMP_index] <= BRAM_RdData_A;
								TMP_index <= 2'd3;
								mem_delay <= 3'd0;
								tmp[2] <= tmp[2] ^ tmp[1];
								R <= R ^ P[ROUND_index + 1];
								substate2 <= UPDATE_L_R;
							end
						end
					end
					else if(substate2 <= UPDATE_L_R) begin
						L <= R ^ (tmp[2] + tmp[0]);
						R <= L;
						ROUND_index <= ROUND_index + 5'd1;
						substate2 <= LOAD_S;
					end
				end
				else begin
					R <= L;
					L <= R ^ P[17];
					ROUND_index <= 5'd0;
					state <= STORE_L_R;
				end
			end
			else if(state == STORE_L_R) begin
				if(ptr < 'd1043) begin
					if(tmp_cnt == 0) begin
						we <= 4'b1111;
						addr <= ptr * 32'd4;
						din <= L;
						ptr <= ptr + 32'd1;
						tmp_cnt <= tmp_cnt + 1'd1;
					end
					else if(tmp_cnt == 1) begin
						we <= 4'b1111;
						addr <= ptr * 32'd4;
						din <= R;
						ptr <= ptr + 32'd1;
						tmp_cnt <= 1'b0;
						state <= ENCRYPT_INIT;
					end
				end
				else begin
					if(first_or_second == 0) begin
						ptr <= 1;
						first_or_second <= 'b1;
						state <= P_XOR_SALT;
						we <= 4'b0000;
					end
					else if (first_or_second == 1) begin
						first_or_second <= 'b0;
						state <= LOOP;
						we <= 4'b0000;
						ptr <= 1;
					end
				end
			end				
			else if(state == P_XOR_SALT) begin
				if(P_index < 'd18) begin
					we <= 4'b1111;
					addr <= P_ARRAY + P_index * 'd4;
					din <= P[P_index] ^ salt[P_index%4];
					P_index <= P_index + 5'd1;
					P[P_index] <= P[P_index] ^ salt[P_index%4];
				end
				else begin
					P_index <= 5'd0;
					L <= 0;
					R <= 0;
					we <= 4'b0000;
					state <= ENCRYPT_INIT;
				end
			end
			else if(state == LOOP) begin
				if(count > 1) begin
					count <= count - 31'd1;
					state <= P_XOR_EXP;
				end
				else begin
					state <= DONE;
				end
			end
			else if(state == DONE) begin
				done <= 32'hFF;
			end	
		end
	end
	
	
  // ------------------------------------------------------
  // Example code to read/write user logic slave model s/w accessible registers
  // 
  // Note:
  // The example code presented here is to show you one way of reading/writing
  // software accessible registers implemented in the user logic slave model.
  // Each bit of the Bus2IP_WrCE/Bus2IP_RdCE signals is configured to correspond
  // to one software accessible register by the top level template. For example,
  // if you have four 32 bit software accessible registers in the user logic,
  // you are basically operating on the following memory mapped registers:
  // 
  //    Bus2IP_WrCE/Bus2IP_RdCE   Memory Mapped Register
  //                     "1000"   C_BASEADDR + 0x0
  //                     "0100"   C_BASEADDR + 0x4
  //                     "0010"   C_BASEADDR + 0x8
  //                     "0001"   C_BASEADDR + 0xC
  // 
  // ------------------------------------------------------

  assign
    slv_reg_write_sel = Bus2IP_WrCE[1:0],
    slv_reg_read_sel  = Bus2IP_RdCE[1:0],
    slv_write_ack     = Bus2IP_WrCE[0] || Bus2IP_WrCE[1],
    slv_read_ack      = Bus2IP_RdCE[0] || Bus2IP_RdCE[1];

  // implement slave model register(s)
  always @( posedge Bus2IP_Clk )
    begin: SLAVE_REG_WRITE_PROC

      if ( Bus2IP_Resetn == 0 )
        begin
          slv_reg0 <= 0;
          slv_reg1 <= 0;
        end
      else
        case ( slv_reg_write_sel )
          2'b10 :
            for ( byte_index = 0; byte_index <= (C_SLV_DWIDTH/8)-1; byte_index = byte_index+1 )
              if ( Bus2IP_BE[byte_index] == 1 )
                for ( bit_index = byte_index*8; bit_index <= byte_index*8+7; bit_index = bit_index+1 )
                  slv_reg0[bit_index] <= Bus2IP_Data[bit_index];
          2'b01 :
            for ( byte_index = 0; byte_index <= (C_SLV_DWIDTH/8)-1; byte_index = byte_index+1 )
              if ( Bus2IP_BE[byte_index] == 1 )
                for ( bit_index = byte_index*8; bit_index <= byte_index*8+7; bit_index = bit_index+1 )
                  slv_reg1[bit_index] <= Bus2IP_Data[bit_index];
          default : ;
        endcase

    end // SLAVE_REG_WRITE_PROC

  // implement slave model register read mux
  always @( slv_reg_read_sel or slv_reg0 or slv_reg1 )
    begin: SLAVE_REG_READ_PROC

      case ( slv_reg_read_sel )
        2'b10 : slv_ip2bus_data <= slv_reg0;
        2'b01 : slv_ip2bus_data <= done;
        default : slv_ip2bus_data <= 0;
      endcase

    end // SLAVE_REG_READ_PROC

//  ------------------------------------------
// Example code to demonstrate user logic master model functionality
// 
// Note:
// The example code presented here is to show you one way of instatiating
// the AXI4 (Burst) master interface under user control. It is provided for
// demonstration purposes only and allows the user to exercise the AXI4 (Burst)
// master interface during test and evaluation of the template.
// This user logic master model contains a 16-byte flattened register and
// the user is required to initialize the value to desire and then write to
// the model's 'Go' port to initiate the user logic master operation.
//
//    Control Register     (C_BASEADDR + OFFSET + 0x0):
//       bit 0    - Rd     (Read Request Control)
//       bit 1    - Wr     (Write Request Control)
//       bit 2    - BL     (Bus Lock Control)
//       bit 3    - Brst   (Burst Assertion Control)
//       bit 4-7  - Spare  (Spare Control Bits)
//    Status Register      (C_BASEADDR + OFFSET + 0x1):
//       bit 0    - Done   (Transfer Done Status)
//       bit 1    - Busy   (User Logic Master is Busy)
//       bit 2    - Error  (User Logic Master request got error response)
//       bit 3    - Tmout  (User Logic Master request is timeout)
//       bit 2-7  - Spare  (Spare Status Bits)
//    Addrress Register    (C_BASEADDR + OFFSET + 0x4):
//       bit 0-31 - Target Address (This 32-bit value is used to populate the
//                  ip2bus_Mst_Addr(0:31) address bus during a Read or Write
//                  user logic master operation)
//    Byte Enable Register (C_BASEADDR + OFFSET + 0x8):
//       bit 0-15 - Master BE (This 16-bit value is used to populate the
//                  ip2bus_Mst_BE byte enable bus during a Read or Write user
//                  logic master operation for single data beat transfer)
//    Length Register      (C_BASEADDR + OFFSET + 0xC):
//       bit 0-3  - Reserved
//       bit 4-15 - Transfer Length (This 12-bit value is used to populate the
//                  ip2bus_Mst_Length(0:11) transfer length bus which specifies
//                  the number of bytes (1 to 4095) to transfer during user logic
//                  master Read or Write fixed length burst operations)
//    Go Register          (C_BASEADDR + OFFSET + 0xF):
//       bit 0-7  - Go Port (Write to this byte address initiates the user
//                  logic master transfer, data key value of 0x0A must be used)
// 
//    Note: OFFSET may be different depending on your address space configuration,
//          by default it's 0x100. Refer to IPIF address range array
//          for actual value.
// 
// Here's an example procedure in your software application to initiate a 64-byte
// read operation (single data beat) of this master model:
//    1. write 0x09 to the control register to perform write operation.
//    2. write the target address to the address register.
//    3. write valid byte lane value to the be register
//      - note: this value must be aligned with ip2bus address  
//    4. write 0x040 to the length register
//    5. write 0x0a to the go register, this will start the master write operation
//
// Here's an example procedure in your software application to initiate a 64-byte
// write operation (single data beat) of this master model:
//   1. write 0x0A to the control register to perform write operation.
//   2. write the target address to the address register
//   3. write valid byte lane value to the be register
//      - note: this value must be aligned with ip2bus address
//   4. write 0x0040 to the length register
//   5. write 0x0a to the go register, this will start the master write operation
// 
//----------------------------------------
  assign mst_reg_write_req = Bus2IP_WrCE[2] || Bus2IP_WrCE[3] || Bus2IP_WrCE[4] || Bus2IP_WrCE[5];
  assign mst_reg_read_req  = Bus2IP_RdCE[2] || Bus2IP_RdCE[3] || Bus2IP_RdCE[4] || Bus2IP_RdCE[5];
  assign mst_reg_write_sel = Bus2IP_WrCE[5 : 2];
  assign mst_reg_read_sel  = Bus2IP_RdCE[5 : 2];
  assign mst_write_ack     = mst_reg_write_req;
  assign mst_read_ack      = mst_reg_read_req;

  // rip control bits from master model registers
  assign mst_cntl_rd_req   = mst_reg[0][0];
  assign mst_cntl_wr_req   = mst_reg[0][1];
  assign mst_cntl_bus_lock = mst_reg[0][2];
  assign mst_cntl_burst    = mst_reg[0][3];
  assign mst_ip2bus_addr   = {mst_reg[7], mst_reg[6], mst_reg[5], mst_reg[4]};
  assign mst_ip2bus_be     = {mst_reg[9], mst_reg[8]};
  assign mst_xfer_reg_len  = {mst_reg[14][3 : 0], mst_reg[13], mst_reg[12]};// changed to 20 bits 
  assign mst_xfer_length   = mst_xfer_reg_len[C_LENGTH_WIDTH-1 : 0];

  // implement byte write enable for each byte slice of the master model registers
  always @ (Bus2IP_BE or mst_reg_write_req or mst_reg_write_sel)
    begin
      for ( byte_index = 0; byte_index <= 15; byte_index = byte_index+1 )
        mst_byte_we[byte_index] <= mst_reg_write_req & mst_reg_write_sel[3 - (byte_index/BE_WIDTH)] & Bus2IP_BE[byte_index - ((byte_index/BE_WIDTH)*BE_WIDTH)];
    end // MASTER_REG_BYTE_WR_EN
  // implement master model registers
  // The master registers are written to initialize master transfer.
  always @ ( posedge Bus2IP_Clk)
    begin
    if (Bus2IP_Resetn == 1'b0 )
      begin
        for ( byte_index = 0; byte_index <= 14; byte_index = byte_index+1 ) 
          mst_reg[byte_index] <= 0;
      end
    else 
      begin 
          if ( mst_byte_we[0] == 1'b1 )
            begin
              mst_reg[0][7:0] <= Bus2IP_Data[7 : 0];
            end
          
    		 mst_reg[1][1] <= mst_cmd_sm_busy;  
      
          if (mst_byte_we[1] == 1'b1 )
          // allows a clear of the 'Done'/'error'/'timeout'
            begin
              mst_reg[1][0] <= Bus2IP_Data[(1-(1/BE_WIDTH)*BE_WIDTH)*8];
              mst_reg[1][2] <= Bus2IP_Data[(1-(1/BE_WIDTH)*BE_WIDTH)*8+2];
              mst_reg[1][3] <= Bus2IP_Data[(1-(1/BE_WIDTH)*BE_WIDTH)*8+3];
            end
        else
          // 'Done'/'error'/'timeout' from master control state machine
          begin
             mst_reg[1][0]  <= mst_cmd_sm_set_done | mst_reg[1][0];
             mst_reg[1][2]  <= mst_cmd_sm_set_error | mst_reg[1][2];
             mst_reg[1][3]  <= mst_cmd_sm_set_timeout | mst_reg[1][3];
           end
             // byte 2 and 3 are reserved
             // address register (byte 4 to 7)
             // be register (byte 8 to 9)
             // length register (byte 12 to 13)
             // byte 10, 11 and 14 are reserved
         for ( byte_index = 4; byte_index <= 14; byte_index = byte_index+1 )
           if ( mst_byte_we[byte_index] == 1'b1 )
             begin
               mst_reg[byte_index] <= Bus2IP_Data[(byte_index-(byte_index/BE_WIDTH)*BE_WIDTH)*8 +: 8];
             end
      end
    end // MASTER_REG_WRITE_PROC
  // implement master model write only 'go' port to trigger start of master rd/wr transaction
  always @ ( posedge Bus2IP_Clk)
    begin
      if (Bus2IP_Resetn == 1'b0 || mst_cmd_sm_clr_go == 1'b1 )
        begin
          mst_go <= 1'b0;
        end
      else  
        if ( mst_cmd_sm_busy == 1'b0 && mst_byte_we[GO_BYTE_LANE] == 1'b1 && Bus2IP_Data[(GO_BYTE_LANE-(GO_BYTE_LANE/BE_WIDTH)*BE_WIDTH)*8 +: 8] == GO_DATA_KEY)
          begin
            mst_go   <= 1'b1;
          end
    end

  // implement master model register read mux
  always @ ( mst_reg_read_sel, mst_reg ) 
  begin

    case(mst_reg_read_sel)
      4'b1000:
        for(byte_index = 0; byte_index <= BE_WIDTH-1;byte_index = byte_index+1)
          mst_ip2bus_data[byte_index*8 +:8] <= mst_reg[byte_index];
      4'b0100:
        for(byte_index = 0; byte_index <= BE_WIDTH-1;byte_index = byte_index+1)
          mst_ip2bus_data[byte_index*8 +:8] <= mst_reg[BE_WIDTH+byte_index];
      4'b0010:
        for(byte_index = 0; byte_index <= BE_WIDTH-1;byte_index = byte_index+1)
          mst_ip2bus_data[byte_index*8 +:8] <= mst_reg[BE_WIDTH*2+byte_index];
      4'b0001:
        for(byte_index = 0; byte_index <= BE_WIDTH-1; byte_index = byte_index+1)
          if ( byte_index == (BE_WIDTH-1) ) 
            begin
              // go port is not readable
              mst_ip2bus_data[byte_index*8 +: 8] <= 8'b0;
            end
          else
            begin
              mst_ip2bus_data[byte_index*8 +: 8] <= mst_reg[BE_WIDTH*3+byte_index];
            end
        default : 
                   begin
                       mst_ip2bus_data <= 0;
                   end
      endcase
    end //MASTER_REG_READ_PROC	
  // user logic master command interface assignments
  assign ip2bus_mstrd_req  = mst_cmd_sm_rd_req;
  assign ip2bus_mstwr_req  = mst_cmd_sm_wr_req;
  assign ip2bus_mst_addr   = mst_cmd_sm_ip2bus_addr;
  assign ip2bus_mst_be     = mst_cmd_sm_ip2bus_be;
  assign ip2bus_mst_type   = mst_cmd_sm_xfer_type;
  assign ip2bus_mst_length = mst_cmd_sm_xfer_length;
  assign ip2bus_mst_lock   = mst_cmd_sm_bus_lock;
  assign ip2bus_mst_reset  = mst_cmd_sm_reset;

 //implement master command interface state machine
  always @ ( posedge Bus2IP_Clk)
    begin
      if (Bus2IP_Resetn == 1'b0 )
        begin
          // reset condition
          mst_cmd_sm_state          <= CMD_IDLE;
          mst_cmd_sm_clr_go         <= 0;
          mst_cmd_sm_rd_req         <= 0;
          mst_cmd_sm_wr_req         <= 0;
          mst_cmd_sm_bus_lock       <= 0;
          mst_cmd_sm_reset          <= 0;
          mst_cmd_sm_ip2bus_addr    <= 0;
          mst_cmd_sm_ip2bus_be      <= 0;
        mst_cmd_sm_xfer_type      <= 0;
        mst_cmd_sm_xfer_length    <= 0;
          mst_cmd_sm_set_done       <= 0;
          mst_cmd_sm_set_error      <= 0;
          mst_cmd_sm_set_timeout    <= 0;
          mst_cmd_sm_busy           <= 0;
          mst_cmd_sm_start_rd_llink <= 1'b0;
          mst_cmd_sm_start_wr_llink <= 1'b0;
        end
      else  
        begin
          // default condition
          mst_cmd_sm_clr_go         <= 0;
          mst_cmd_sm_rd_req         <= 0;
          mst_cmd_sm_wr_req         <= 0;
          mst_cmd_sm_bus_lock       <= 0;
          mst_cmd_sm_reset          <= 0;
          mst_cmd_sm_ip2bus_addr    <= 0;
          mst_cmd_sm_ip2bus_be      <= 0;
          mst_cmd_sm_xfer_type      <= 0;
          mst_cmd_sm_xfer_length    <= 0;
          mst_cmd_sm_set_done       <= 0;
          mst_cmd_sm_set_error      <= 0;
          mst_cmd_sm_set_timeout    <= 0;
          mst_cmd_sm_busy           <= 1'b1;
          mst_cmd_sm_start_rd_llink <= 1'b0;
          mst_cmd_sm_start_wr_llink <= 1'b0;
          // state transition
          case (mst_cmd_sm_state)

            CMD_IDLE:
               if ( mst_go == 1'b1 ) 
                 begin
                   // 'Go' register is triggerred.
                   mst_cmd_sm_state  <= CMD_RUN;
                   mst_cmd_sm_clr_go <= 1'b1;
                   mst_cmd_sm_busy   <= 1'b1;

                   if ( mst_cntl_rd_req == 1'b1 )
                     begin
                       // Master read local link
                       mst_cmd_sm_start_rd_llink <= 1'b1;
                     end
                   else if ( mst_cntl_wr_req == 1'b1 )
                     begin
    						  // Master write local link
                       mst_cmd_sm_start_wr_llink <= 1'b1;
                     end
                 end
               else
                 begin
                   mst_cmd_sm_state  <= CMD_IDLE;
                   mst_cmd_sm_busy   <= 1'b0;
                 end

            CMD_RUN:
               if ( bus2ip_mst_cmdack == 1'b1 && bus2ip_mst_cmplt == 1'b0 )
                 begin
                   mst_cmd_sm_state <= CMD_WAIT_FOR_DATA;
                 end
               else if ( bus2ip_mst_cmplt == 1'b1 )
                 begin
    				    // Bus to Ip data reception complete
                   mst_cmd_sm_state <= CMD_DONE;

                   if ( bus2ip_mst_cmd_timeout == 1'b1)
                     begin
                     // AXI4LITE address phase timeout
                       mst_cmd_sm_set_error   <= 1'b1;
                       mst_cmd_sm_set_timeout <= 1'b1;
                     end
                   else if ( bus2ip_mst_error == 1'b1)
                     begin
                       mst_cmd_sm_set_error   <= 1'b1;
                     end
                   end
               else
                 begin
                   mst_cmd_sm_state       <= CMD_RUN;
                   mst_cmd_sm_rd_req      <= mst_cntl_rd_req;
                   mst_cmd_sm_wr_req      <= mst_cntl_wr_req;
                   mst_cmd_sm_ip2bus_addr <= mst_ip2bus_addr;
                   mst_cmd_sm_ip2bus_be   <= mst_ip2bus_be[15 : 16-C_MST_NATIVE_DATA_WIDTH/8 ];
                   mst_cmd_sm_xfer_type   <= mst_cntl_burst;
                   mst_cmd_sm_xfer_length <= mst_xfer_length;
                   mst_cmd_sm_bus_lock    <= mst_cntl_bus_lock;
                 end
 
            CMD_WAIT_FOR_DATA:
               if ( bus2ip_mst_cmplt == 1'b1 )
                 begin
                   mst_cmd_sm_state <= CMD_DONE;
                   if ( bus2ip_mst_cmd_timeout == 1'b1 )
                     begin
                       // AXI4LITE address phase timeout
                       mst_cmd_sm_set_error   <= 1'b1;
                       mst_cmd_sm_set_timeout <= 1'b1;
                     end
                   else if ( bus2ip_mst_error == 1'b1 )
                     begin
                       // AXI4LITE data transfer error
                       mst_cmd_sm_set_error   <= 1'b1;
                     end
                   end
               else
                 begin
                   mst_cmd_sm_state <= CMD_WAIT_FOR_DATA;
                 end

            CMD_DONE:
               begin
    				  // Completion of read/write transaction.
                 mst_cmd_sm_state    <= CMD_IDLE;
                 mst_cmd_sm_set_done <= 1'b1;
                 mst_cmd_sm_busy     <= 1'b0;
               end
            default :
               begin
                 mst_cmd_sm_state    <= CMD_IDLE;
                 mst_cmd_sm_busy     <= 1'b0;
               end
          endcase
        end	
    end //MASTER_CMD_SM_PROC

  // user logic master read locallink interface assignments
  assign ip2bus_mstrd_dst_rdy_n = !(mst_llrd_sm_dst_rdy),
         ip2bus_mstrd_dst_dsc_n = 1'b1; // do not throttle data
 // implement a simple state machine to enable the
 // read locallink interface to transfer data
 
 always @ ( posedge Bus2IP_Clk)
   begin
     if (Bus2IP_Resetn == 1'b0 )
       begin
       // reset condition
         mst_llrd_sm_state   <= LLRD_IDLE;
         mst_llrd_sm_dst_rdy <= 1'b0;
       end  
     else
       begin
         // default condition
         mst_llrd_sm_state   <= LLRD_IDLE;
         mst_llrd_sm_dst_rdy <= 1'b0;

         // state transition
         case (mst_llrd_sm_state)

             CMD_IDLE:
                 if ( mst_cmd_sm_start_rd_llink == 1'b1 )
                   begin
                     mst_llrd_sm_state <= LLRD_GO;
                   end
                 else
                   begin
                     mst_llrd_sm_state <= LLRD_IDLE;
                   end

             LLRD_GO:
                 // done, end of packet
                 if ( mst_llrd_sm_dst_rdy == 1'b1 && bus2ip_mstrd_src_rdy_n == 1'b0 &&
                      bus2ip_mstrd_eof_n == 1'b0 )
                   begin
                     mst_llrd_sm_state   <= LLRD_IDLE;
                   end
                 // not done yet, continue receiving data
                 else
                   begin
                     mst_llrd_sm_state   <= LLRD_GO;
                     mst_llrd_sm_dst_rdy <= 1'b1;
                   end

             default : 
                 begin
                   mst_llrd_sm_state <= LLRD_IDLE;
                 end
         endcase
       end	
   end // LLINK_RD_SM_PROCESS
 // user logic master write locallink interface assignments
 assign ip2bus_mstwr_src_rdy_n = !mst_llwr_sm_src_rdy,
        ip2bus_mstwr_src_dsc_n = 1'b1; // do not throttle data
 
 assign ip2bus_mstwr_rem       = 'b0;
 assign ip2bus_mstwr_sof_n     = !mst_llwr_sm_sof;
 assign ip2bus_mstwr_eof_n     = !mst_llwr_sm_eof;
  // implement a simple state machine to enable the
  // write locallink interface to transfer data
  
  always @ ( posedge Bus2IP_Clk)
    begin
      if (Bus2IP_Resetn == 1'b0 )
        begin
          // reset condition
          mst_llwr_sm_state   <= LLWR_IDLE;
          mst_llwr_sm_src_rdy <= 1'b0;
          mst_llwr_sm_sof     <= 1'b0;
          mst_llwr_sm_eof     <= 1'b0;
          mst_llwr_byte_cnt   <= 0;
        end  
      else
        begin
          // default condition
          mst_llwr_sm_state   <= LLWR_IDLE;
          mst_llwr_sm_src_rdy <= 1'b0;
          mst_llwr_sm_sof     <= 1'b0;
          mst_llwr_sm_eof     <= 1'b0;
          mst_llwr_byte_cnt   <= 0;

          // state transition
          case (mst_llwr_sm_state)

              LLWR_IDLE:
                  if ( mst_cmd_sm_start_wr_llink == 1'b1 && mst_cntl_burst == 1'b0 )
                    begin
                      mst_llwr_sm_state <= LLWR_SNGL_INIT;
                    end
                  else if ( mst_cmd_sm_start_wr_llink == 1'b1 && mst_cntl_burst == 1'b1 ) 
                    begin
                      mst_llwr_sm_state <= LLWR_BRST_INIT;
                    end  
                  else
                    begin
                      mst_llwr_sm_state <= LLWR_IDLE;
                    end
 
             LLWR_SNGL_INIT:
                  begin
                    mst_llwr_sm_state   <= LLWR_SNGL;
                    mst_llwr_sm_src_rdy <= 1'b1;
                    mst_llwr_sm_sof     <= 1'b1;
                    mst_llwr_sm_eof     <= 1'b1;
                  end 	

              LLWR_SNGL:
                  // destination discontinue write
                  if ( bus2ip_mstwr_dst_dsc_n == 1'b0 && bus2ip_mstwr_dst_rdy_n == 1'b0 )
                    begin
                      mst_llwr_sm_state   <= LLWR_IDLE;
                      mst_llwr_sm_src_rdy <= 1'b0;
                      mst_llwr_sm_eof     <= 1'b0;
                    end  
                  // single data beat transfer complete
                  else if ( mst_fifo_valid_read_xfer == 1'b1 )
                    begin
                      mst_llwr_sm_state   <= LLWR_IDLE;
                      mst_llwr_sm_src_rdy <= 1'b0;
                      mst_llwr_sm_sof     <= 1'b0;
                      mst_llwr_sm_eof     <= 1'b0;
                    end  
                  // wait on destination
                  else
                    begin
                      mst_llwr_sm_state   <= LLWR_SNGL;
                      mst_llwr_sm_src_rdy <= 1'b1;
                      mst_llwr_sm_sof     <= 1'b1;
                      mst_llwr_sm_eof     <= 1'b1;
                    end

              LLWR_BRST_INIT:
                  begin
                    mst_llwr_sm_state   <= LLWR_BRST;
                    mst_llwr_sm_src_rdy <= 1'b1;
                    mst_llwr_sm_sof     <= 1'b1;
                    mst_llwr_byte_cnt   <=  (mst_xfer_length); // convert to integer
                  end

              LLWR_BRST:
                  begin
                    if ( mst_fifo_valid_read_xfer == 1'b1)
                      begin
                        mst_llwr_sm_sof <= 1'b0;
                      end
                    else
                      begin
                        mst_llwr_sm_sof <= mst_llwr_sm_sof;
                      end
 
                    // destination discontinue write
                    if ( bus2ip_mstwr_dst_dsc_n == 1'b0 &&
                         bus2ip_mstwr_dst_rdy_n == 1'b0 )
                      begin 
                        mst_llwr_sm_state   <= LLWR_IDLE;
                        mst_llwr_sm_src_rdy <= 1'b1;
                        mst_llwr_sm_eof     <= 1'b1;
                      end  
                    // last data beat write
                    else if ( mst_fifo_valid_read_xfer == 1'b1 &&
                            ( mst_llwr_byte_cnt-BYTES_PER_BEAT) <= BYTES_PER_BEAT )
                      begin
                        mst_llwr_sm_state   <= LLWR_BRST_LAST_BEAT;
                        mst_llwr_sm_src_rdy <= 1'b1;
                        mst_llwr_sm_eof     <= 1'b1;
                      end  
                    // wait on destination
                    else
                      begin
                        mst_llwr_sm_state   <= LLWR_BRST;
                        mst_llwr_sm_src_rdy <= 1'b1;
                        // decrement write transfer counter if it's a valid write
                        if ( mst_fifo_valid_read_xfer == 1'b1 ) 
                          begin
                            mst_llwr_byte_cnt <= mst_llwr_byte_cnt - BYTES_PER_BEAT;
                          end
                        else
                          begin
                            mst_llwr_byte_cnt <= mst_llwr_byte_cnt;
                          end 	
                      end 
                  end
 
              LLWR_BRST_LAST_BEAT:
                  // destination discontinue write
                  if ( bus2ip_mstwr_dst_dsc_n == 1'b0 &&
                       bus2ip_mstwr_dst_rdy_n == 1'b0 ) 
                    begin		
                      mst_llwr_sm_state   <= LLWR_IDLE;
                      mst_llwr_sm_src_rdy <= 1'b0;
                    end  
                  // last data beat done
                  else if ( mst_fifo_valid_read_xfer == 1'b1 )
                    begin
                      mst_llwr_sm_state   <= LLWR_IDLE;
                      mst_llwr_sm_src_rdy <= 1'b0;
                    end  
                  // wait on destination
                  else
                    begin
                      mst_llwr_sm_state   <= LLWR_BRST_LAST_BEAT;
                      mst_llwr_sm_src_rdy <= 1'b1;
                      mst_llwr_sm_eof     <= 1'b1;
                    end	  
 
              default : 
                  begin
                    mst_llwr_sm_state <= LLWR_IDLE;
                  end
          endcase
        end	
    end // LLINK_WR_SM_PROC
  // local srl fifo for data storage
  assign mst_fifo_valid_write_xfer = !bus2ip_mstrd_src_rdy_n & mst_llrd_sm_dst_rdy;
  assign mst_fifo_valid_read_xfer  = !bus2ip_mstwr_dst_rdy_n & mst_llwr_sm_src_rdy;
  assign bus2ip_Reset   = !Bus2IP_Resetn;
 
  // FIFO depth is 128 words. User can modify the depth based on their requirement.
   srl_fifo_f #(
     .C_DWIDTH(C_MST_NATIVE_DATA_WIDTH),
     .C_DEPTH(128))
   DATA_CAPTURE_FIFO_I (
     .Clk(Bus2IP_Clk),
     .Reset(bus2ip_Reset),
     .FIFO_Write(mst_fifo_valid_write_xfer),
     .Data_In(bus2ip_mstrd_d),
     .FIFO_Read(mst_fifo_valid_read_xfer),
     .Data_Out(ip2bus_mstwr_d),
     .FIFO_Full(),
     .FIFO_Empty(),
     .Addr()); // DATA_CAPTURE_FIFO_I
 
  // ------------------------------------------------------------
  // Example code to drive IP to Bus signals
  // ------------------------------------------------------------

  assign IP2Bus_Data = (slv_read_ack == 1'b1) ? slv_ip2bus_data : (mst_read_ack == 1'b1) ? mst_ip2bus_data :  0 ;

  assign IP2Bus_WrAck = slv_write_ack || mst_write_ack;
  assign IP2Bus_RdAck = slv_read_ack || mst_read_ack;
  assign IP2Bus_Error = 0;

endmodule

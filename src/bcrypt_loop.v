/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Katja Malvoni <kmalvoni at gmail dot com>
 * It is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted.
 */

module bcrypt_loop
(
  clk,
  BRAM_WE_A,
  BRAM_Addr_A,
  BRAM_WrData_A,
  BRAM_RdData_A, 
  start,
  done,
  core_index
);

parameter INIT				= 4'b0000;
parameter P_XOR_EXP			= 4'b0001;
parameter ENCRYPT_INIT			= 4'b0010;
parameter FEISTEL			= 4'b0011;
parameter STORE_L_R			= 4'b0100;
parameter P_XOR_SALT			= 4'b0101;
parameter LOOP				= 4'b0110;
parameter DONE				= 4'b0111;
parameter SET				= 4'b1000;
parameter LOAD_P			= 4'b1001;	
parameter LOAD_EXP_KEY			= 4'b1010;
parameter LOAD_SALT			= 4'b1011;
parameter LOAD_S			= 4'b1100;
parameter UPDATE_L_R			= 4'b1101;
parameter STORE_P			= 4'b1110;
parameter STORE_S			= 4'b1111;
	
parameter P_ARRAY			= 32'b0000000000000000;
parameter P_S0				= 32'b0000000001001000;
parameter P_EXP_KEY			= 32'b0001000001001000;
parameter P_SALT			= 32'b0001000010010000;
parameter COUNT			= 32'd4256;
parameter OFFSET			= 32'd4260;

parameter C_MST_NATIVE_DATA_WIDTH      = 32;
parameter C_LENGTH_WIDTH               = 12;
parameter C_MST_AWIDTH                 = 32;
parameter C_NUM_REG                    = 6;
parameter C_SLV_DWIDTH                 = 32;

input				    	clk;
output     [C_SLV_DWIDTH/8 - 1 : 0]  	BRAM_WE_A;
output     [C_MST_AWIDTH - 1 : 0]    	BRAM_Addr_A;
output     [C_SLV_DWIDTH - 1 : 0]    	BRAM_WrData_A;
input      [C_SLV_DWIDTH - 1 : 0]    	BRAM_RdData_A;
input      [C_SLV_DWIDTH-1 : 0]      	start;
output     [C_SLV_DWIDTH-1 : 0]      	done;
input      [7 : 0]			core_index;

integer i = 0;
  
reg [C_SLV_DWIDTH-1 : 0] done_reg;
reg [4:0] P_index = 0;
reg [10:0] S_index = 0;
reg [4:0] EXP_KEY_index = 0;
reg [2:0] SALT_index = 0;
reg [4:0] ROUND_index = 0;
reg [31:0] ptr = 0;
reg tmp_cnt = 0;
reg first_or_second = 0;
reg [2:0] mem_delay = 0;
reg [31:0] count = 0;

reg [31:0] L = 0;
reg [31:0] R = 0;
reg [3:0] state = INIT;
reg [3:0] substate1 = SET;
reg [3:0] substate2 = 0;
reg [3:0] substate3 = 0;
reg [31:0] P [17:0];
reg [31:0] exp_key [17:0];
reg [31:0] salt [3:0];

reg [31:0] p_addr;
reg [31:0] s0_addr;  
reg [31:0] exp_key_addr;
reg [31:0] salt_addr;
reg [31:0] count_addr;
		
reg wea_1;
reg web_1;		
reg wea_2;
reg web_2;
reg [3:0] we;
reg [31:0] addr;
reg [9:0] addra_1;
reg [9:0] addrb_1;
reg [9:0] addra_2;
reg [9:0] addrb_2;
reg [31:0] din;
reg [31:0] dina_1;
reg [31:0] dinb_1;
wire [31:0] douta_1;
wire [31:0] doutb_1;
wire ckla_1, clkb_1;
reg [31:0] dina_2;
reg [31:0] dinb_2;
wire [31:0] douta_2;
wire [31:0] doutb_2;
wire ckla_2, clkb_2;

ram mem1(clka_1, wea_1, addra_1, dina_1, douta_1, clkb_1, web_1, addrb_1, dinb_1, doutb_1);
ram mem2(clka_2, wea_2, addra_2, dina_2, douta_2, clkb_2, web_2, addrb_2, dinb_2, doutb_2);

assign clka_1 = clk;
assign clkb_1 = clk;
assign clka_2 = clk;
assign clkb_2 = clk;

assign BRAM_WE_A = we;
assign BRAM_WrData_A = din;
assign BRAM_Addr_A = addr;
assign done = done_reg;

always @ (posedge clk)
begin
	if(start == 0) begin
		we <= 4'b0000;
		wea_1 <= 0;
		web_1 <= 0;
		wea_2 <= 0;
		web_2 <= 0;
		count <= 0;
		p_addr <= P_ARRAY + OFFSET * core_index;
		s0_addr <= P_S0 + OFFSET * core_index;
		exp_key_addr <= P_EXP_KEY + OFFSET * core_index;
		salt_addr <= P_SALT + OFFSET * core_index;
		count_addr <= COUNT + OFFSET * core_index;
		state <= INIT;
		substate1 <= SET;
		done_reg <= 0;
	end
	else if(start == 1) begin
		if(state == INIT) begin
			if(substate1 == SET) begin
				if(mem_delay < 3'd3) begin
					addr <= count_addr;
					mem_delay <= mem_delay + 1;
				end
				else begin
					count <= 32'd1 << BRAM_RdData_A;
					substate1 <= LOAD_EXP_KEY;
					mem_delay <= 0;
					p_addr <= P_ARRAY + OFFSET * core_index;
					s0_addr <= P_S0 + OFFSET * core_index;
					exp_key_addr <= P_EXP_KEY + OFFSET * core_index;
					salt_addr <= P_SALT + OFFSET * core_index;
				end
			end
			else if(substate1 == LOAD_EXP_KEY) begin
				if(EXP_KEY_index < 'd18) begin
					if(mem_delay < 3'd3) begin
						addr <= exp_key_addr;
						mem_delay <= mem_delay + 1;
					end
					else begin
						exp_key[EXP_KEY_index] <= BRAM_RdData_A;
						EXP_KEY_index <= EXP_KEY_index + 'd1;
						exp_key_addr <= exp_key_addr + 32'd4;
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
				if(SALT_index < 'd4) begin
					if(mem_delay < 3'd3) begin
						addr <= salt_addr;
						mem_delay <= mem_delay + 3'd1;
					end
					else begin
						salt[SALT_index] <= BRAM_RdData_A;
						SALT_index <= SALT_index + 3'd1;
						salt_addr <= salt_addr + 32'd4;
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
					if(mem_delay < 3'd3) begin
						addr <= p_addr;
						mem_delay <= mem_delay + 3'd1;
					end
					else begin
						P[P_index] <= BRAM_RdData_A;
						P_index <= P_index + 5'd1;
						p_addr <= p_addr + 32'd4;
						mem_delay <= 3'd0;
					end
				end
				else begin
					P_index <= 5'd0;
					S_index <= 'd0;
					mem_delay <= 3'd0;
					substate1 <=  LOAD_S;
				end
			end
			else if(substate1 == LOAD_S) begin
				if(S_index < 'd1024) begin
					if(mem_delay < 3'd3) begin
						wea_1 <= 0;
						wea_2 <= 0;
						addr <= s0_addr;
						mem_delay <= mem_delay + 3'd1;
					end
					else begin
						wea_1 <= 1;
						wea_2 <= 1;
						addra_1 <= S_index;
						addra_2 <= S_index;
						dina_1 <= BRAM_RdData_A;
						dina_2 <= BRAM_RdData_A;
						S_index <= S_index + 5'd1;
						s0_addr <= s0_addr + 32'd4;
						mem_delay <= 3'd0;
					end
				end
				else begin
					wea_1 <= 0;
					wea_2 <= 0;
					S_index <= 5'd0;
					mem_delay <= 3'd0;
					state <=  P_XOR_EXP;
					substate1 <= P_XOR_EXP;
					done_reg <= 'd1;
				end
			end
		end
	end
	else if (start == 2) begin
		if(state == P_XOR_EXP) begin
			if(P_index < 5'd18) begin
				P[P_index] <= P[P_index] ^ exp_key[P_index];
				P[P_index + 'd1] <= P[P_index + 'd1] ^ exp_key[P_index + 'd1];
				P_index <= P_index + 5'd2;
			end
			else begin
				P_index <= 5'd0;
				L <= 0;
				R <= 0;
				state <= ENCRYPT_INIT;
				ptr <= 0;
			end
		end
	else if(state == ENCRYPT_INIT) begin
			mem_delay <= 3'd0;
			L <= L ^ P[0];
			state <= FEISTEL;
			substate2 <= LOAD_S;
			wea_1 <= 0;
			web_1 <= 0;
			wea_2 <= 0;
			web_2 <= 0;
			addra_1[9:8] <= 'b00;
			addrb_1[9:8] <= 'b01;
			addra_2[9:8] <= 'b10;
			addrb_2[9:8] <= 'b11;
		end
		else if(state == FEISTEL) begin
			if(ROUND_index < 16) begin
				if(mem_delay == 0) begin
					if (ROUND_index > 0) begin
						L <= (R ^ P[ROUND_index]) ^ (((douta_1 + doutb_1) ^ douta_2) + doutb_2);
						R <= L;
						mem_delay <= 0;
					end
					if (ROUND_index == 0) begin
						addra_1 <= L[31:24];
						addrb_1 <= 10'h100 + L[23:16];
						addra_2 <= 10'h200 + L[15:8];
						addrb_2 <= 10'h300 + L[7:0];
					end
					else begin
						addra_1[7:0] <= (((R ^ P[ROUND_index]) ^ (((douta_1 + doutb_1) ^ douta_2) + doutb_2))&32'hFF000000)>>24;
						addrb_1[7:0] <= (((R ^ P[ROUND_index]) ^ (((douta_1 + doutb_1) ^ douta_2) + doutb_2))&32'h00FF0000)>>16;
						addra_2[7:0] <= (((R ^ P[ROUND_index]) ^ (((douta_1 + doutb_1) ^ douta_2) + doutb_2))&32'h0000FF00)>>8;
						addrb_2[7:0] <= ((R ^ P[ROUND_index]) ^ (((douta_1 + doutb_1) ^ douta_2) + doutb_2))&32'h000000FF;
					end
					mem_delay <= mem_delay + 3'd1;
				end
				else if (mem_delay == 1) begin
					ROUND_index <= ROUND_index + 5'd1;
					mem_delay <= 0;
				end
			end
			else begin
				R <= (R ^ P[16]) ^ (((douta_1 + doutb_1) ^ douta_2) + doutb_2);
				L <= L ^ P[17];
				ROUND_index <= 5'd0;
				state <= STORE_L_R;
			end
		end
		else if(state == STORE_L_R) begin
			if(ptr < 'd18) begin
				P[ptr] <= L;
				P[ptr + 'd1] <= R;
				ptr <= ptr + 'd2;
				state <= ENCRYPT_INIT;
			end
			else if(ptr >= 'd18 && ptr < 'd1042) begin
				wea_1 <= 1;
				web_1 <= 1;
				wea_2 <= 1;
				web_2 <= 1;
				addra_1 <= ptr - 'd18;
				dina_1 <= L;
				addra_2 <= ptr - 'd18;
				dina_2 <= L;
				addrb_1 <= ptr - 'd17;
				dinb_1 <= R;
				addrb_2 <= ptr - 'd17;
				dinb_2 <= R;
				ptr <= ptr + 'd2;
				state <= ENCRYPT_INIT;
			end
			else begin
				if(first_or_second == 0) begin
					ptr <= 0;
					first_or_second <= 'b1;
					state <= P_XOR_SALT;
					wea_1 <= 0;
					web_1 <= 0;
					wea_2 <= 0;
					web_2 <= 0;
				end
				else if (first_or_second == 1) begin
					first_or_second <= 'b0;
					state <= LOOP;
					wea_1 <= 0;
					web_1 <= 0;
					wea_2 <= 0;
					web_2 <= 0;
					ptr <= 0;
				end
			end
		end			
		else if(state == P_XOR_SALT) begin
			if(P_index < 'd18) begin
				P[P_index] <= P[P_index] ^ salt[P_index%4];
				P[P_index + 'd1] <= P[P_index + 'd1] ^ salt[(P_index + 'd1)%4];
				P_index <= P_index + 5'd2;
			end
			else begin
				P_index <= 5'd0;
				L <= 0;
				R <= 0;
				state <= ENCRYPT_INIT;
			end
		end
		else if(state == LOOP) begin
			if(count > 1) begin
				count <= count - 32'd1;
				state <= P_XOR_EXP;
			end
			else begin
				state <= DONE;
				substate3 <= STORE_P;
				done_reg <= 2;
				P_index <= 0;
				s0_addr <= P_S0 + OFFSET * core_index;
				p_addr <= P_ARRAY + OFFSET * core_index;
			end
		end
	end
	else if (start == 3) begin
		if(state == DONE) begin
			if(substate3 == STORE_P) begin
				if(P_index < 'd18) begin
					we <= 4'b1111;
					addr <= p_addr;
					din <= P[P_index];
					P_index <= P_index + 'd1;
					p_addr <= p_addr + 32'd4;
				end
				else begin
					P_index <= 0;
					we <= 4'b0000;
					S_index <= 0;
					substate3 <= STORE_S;
				end
			end
			else if(substate3 == STORE_S) begin
				if(S_index < 'd1024) begin
					if(mem_delay < 3'd2) begin
						we <= 4'b0000;
						addra_1 <= S_index;
						mem_delay <= mem_delay + 'd1;
					end
					else begin
						we <= 4'b1111;
						addr <= s0_addr;
						din <= douta_1;
						mem_delay <= 0;
						S_index <= S_index + 'd1;
						s0_addr <= s0_addr + 32'd4;
					end
				end
				else begin
					we <= 4'b0000;
					substate3 <= DONE;
				end
			end
			else if(substate3 == DONE) begin
				done_reg <= 32'hFF;
			end
		end	
	end
end

endmodule
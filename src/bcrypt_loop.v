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
  BRAM_Rst_A,
  BRAM_Clk_A,
  BRAM_En_A,
  BRAM_WE_A,
  BRAM_Addr_A,
  BRAM_WrData_A,
  BRAM_RdData_A, 
  slv_reg0,
  done
);

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
parameter COUNT_ADDR		= 32'd4260;

parameter C_MST_NATIVE_DATA_WIDTH        = 32;
parameter C_LENGTH_WIDTH                 = 12;
parameter C_MST_AWIDTH                   = 32;
parameter C_NUM_REG                      = 6;
parameter C_SLV_DWIDTH                   = 32;

input				     clk;
output                               BRAM_Rst_A;
output                               BRAM_Clk_A;
output                               BRAM_En_A;
output     [C_SLV_DWIDTH/8 - 1 : 0]  BRAM_WE_A;
output     [C_MST_AWIDTH - 1 : 0]    BRAM_Addr_A;
output     [C_SLV_DWIDTH - 1 : 0]    BRAM_WrData_A;
input      [C_SLV_DWIDTH - 1 : 0]    BRAM_RdData_A;
input      [C_SLV_DWIDTH-1 : 0]      slv_reg0;
output     [C_SLV_DWIDTH-1 : 0]      done;

integer i = 0;
  
reg [C_SLV_DWIDTH-1 : 0] done_reg;
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

assign BRAM_Clk_A = clk;
assign BRAM_En_A = 1'b1;
assign BRAM_Rst_A = 1'b0;
assign BRAM_WE_A = we;
assign BRAM_WrData_A = din;
assign BRAM_Addr_A = addr;
assign done = done_reg;

always @ (posedge clk)
begin
	if(slv_reg0 == 0) begin
		we <= 4'b0000;
		en <= 0;
		count <= 0;
		state <= INIT;
		substate1 <= SET;
		done_reg <= 0;
	end
	else if(slv_reg0 != 0) begin
		if(state == INIT) begin
			if(substate1 == SET) begin
				if(mem_delay < 3'd2) begin
					addr <= COUNT_ADDR;
					mem_delay <= mem_delay + 1;
				end
				else begin
					count <= 32'd1 << BRAM_RdData_A;
					substate1 <= LOAD_EXP_KEY;
					mem_delay <= 0;
					en <= 1;
				end
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
			done_reg <= 32'hFF;
		end	
	end
end

endmodule

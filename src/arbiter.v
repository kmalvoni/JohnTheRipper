/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Katja Malvoni <kmalvoni at gmail dot com>
 * It is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted.
 */
module arbiter (
	clk,
	slv_reg0,
	BRAM_Rst_A,
	BRAM_Clk_A,
	BRAM_En_A,
	BRAM_WE_A,
	BRAM_Addr_A,
	BRAM_WrData_A,
	BRAM_RdData_A,
	all_done
);

parameter NUM_OF_CORES			= 14;
parameter INIT				= 3'b000;
parameter LOAD_DATA			= 3'b001;
parameter WAIT_LOAD			= 3'b010;
parameter COMPUTE			= 3'b011;
parameter WAIT_COMPUTE			= 3'b100;
parameter STORE_DATA			= 3'b101;
parameter WAIT_STORE			= 3'b110;
parameter DONE				= 3'b111;
parameter OFFSET			= 32'd4260;

parameter C_SLV_DWIDTH                   = 32;
parameter C_MST_AWIDTH                   = 32;

input				     clk;
input       [C_SLV_DWIDTH-1 : 0]     slv_reg0;
output                               BRAM_Rst_A;
output                               BRAM_Clk_A;
output                               BRAM_En_A;
output     [C_SLV_DWIDTH/8 - 1 : 0]  BRAM_WE_A;
output     [C_MST_AWIDTH - 1 : 0]    BRAM_Addr_A; 
output     [C_SLV_DWIDTH - 1 : 0]    BRAM_WrData_A;
input      [C_SLV_DWIDTH - 1 : 0]    BRAM_RdData_A;
output	   [C_SLV_DWIDTH - 1 : 0]    all_done;

wire [C_SLV_DWIDTH-1 : 0] done [NUM_OF_CORES - 1 : 0];
reg [C_SLV_DWIDTH-1 : 0] all_done_reg;
wire [C_SLV_DWIDTH-1 : 0] start [NUM_OF_CORES - 1 : 0];
reg [C_SLV_DWIDTH-1 : 0] start_reg [NUM_OF_CORES - 1 : 0];
 
  reg [7 : 0] core_index = 0;
  reg [2 : 0] state = 0;
 
  reg [C_SLV_DWIDTH/8 - 1 : 0] we;
  reg [C_MST_AWIDTH - 1 : 0] addr;
  reg [C_SLV_DWIDTH - 1 : 0] din;
 
  wire [3 : 0] WE_A [NUM_OF_CORES - 1 : 0];
  wire [C_MST_AWIDTH - 1 : 0] Addr_A [NUM_OF_CORES - 1 : 0];
  wire [C_SLV_DWIDTH - 1 : 0] WrData_A [NUM_OF_CORES - 1 : 0];
  
  assign start[0] = start_reg[0];
  assign start[1] = start_reg[1];
  assign start[2] = start_reg[2];
  assign start[3] = start_reg[3];
  assign start[4] = start_reg[4];
  assign start[5] = start_reg[5];
  assign start[6] = start_reg[6];
  assign start[7] = start_reg[7];
  assign start[8] = start_reg[8];
  assign start[9] = start_reg[9];
  assign start[10] = start_reg[10];
  assign start[11] = start_reg[11];
  assign start[12] = start_reg[12];
  assign start[13] = start_reg[13];
  
  assign all_done = all_done_reg;
  
  assign BRAM_Clk_A = clk;
  assign BRAM_En_A = 1'b1;
  assign BRAM_Rst_A = 1'b0;
  assign BRAM_WE_A = we;
  assign BRAM_WrData_A = din;
  assign BRAM_Addr_A = addr;
  
  bcrypt_loop bcrypt0 (clk, WE_A[0], Addr_A[0], WrData_A[0], BRAM_RdData_A, start[0], done[0], 8'd0);
  bcrypt_loop bcrypt1 (clk, WE_A[1], Addr_A[1], WrData_A[1], BRAM_RdData_A, start[1], done[1], 8'd1);
  bcrypt_loop bcrypt2 (clk, WE_A[2], Addr_A[2], WrData_A[2], BRAM_RdData_A, start[2], done[2], 8'd2);
  bcrypt_loop bcrypt3 (clk, WE_A[3], Addr_A[3], WrData_A[3], BRAM_RdData_A, start[3], done[3], 8'd3);
  bcrypt_loop bcrypt4 (clk, WE_A[4], Addr_A[4], WrData_A[4], BRAM_RdData_A, start[4], done[4], 8'd4);
  bcrypt_loop bcrypt5 (clk, WE_A[5], Addr_A[5], WrData_A[5], BRAM_RdData_A, start[5], done[5], 8'd5);
  bcrypt_loop bcrypt6 (clk, WE_A[6], Addr_A[6], WrData_A[6], BRAM_RdData_A, start[6], done[6], 8'd6);
  bcrypt_loop bcrypt7 (clk, WE_A[7], Addr_A[7], WrData_A[7], BRAM_RdData_A, start[7], done[7], 8'd7);
  
  bcrypt_loop bcrypt8 (clk, WE_A[8], Addr_A[8], WrData_A[8], BRAM_RdData_A, start[8], done[8], 8'd8);
  bcrypt_loop bcrypt9 (clk, WE_A[9], Addr_A[9], WrData_A[9], BRAM_RdData_A, start[9], done[9], 8'd9);
  bcrypt_loop bcrypt10 (clk, WE_A[10], Addr_A[10], WrData_A[10], BRAM_RdData_A, start[10], done[10], 8'd10);
  bcrypt_loop bcrypt11 (clk, WE_A[11], Addr_A[11], WrData_A[11], BRAM_RdData_A, start[11], done[11], 8'd11);
  bcrypt_loop bcrypt12 (clk, WE_A[12], Addr_A[12], WrData_A[12], BRAM_RdData_A, start[12], done[12], 8'd12);
  bcrypt_loop bcrypt13 (clk, WE_A[13], Addr_A[13], WrData_A[13], BRAM_RdData_A, start[13], done[13], 8'd13);
  
  always @ (posedge clk)
  begin
  	if(slv_reg0 == 0) begin
  		state <= LOAD_DATA;
  		core_index <= 0;
  		all_done_reg <= 0;
  	end
  	else if (slv_reg0 != 0) begin
  		if (state == LOAD_DATA) begin
  			if(core_index < NUM_OF_CORES) begin
  				start_reg[core_index] <= 32'd1;
  				state <= WAIT_LOAD;
  			end
  			else begin
  				core_index <= 32'd0;
  				state <= COMPUTE;
  			end
  		end
  		else if (state == WAIT_LOAD) begin
  			if(core_index < NUM_OF_CORES) begin
  				if(done[core_index] != 32'd1) begin
  					core_index <= core_index;
  					state <= WAIT_LOAD;
  				end
  				else begin
  					state <= LOAD_DATA;
  					core_index <= core_index + 32'd1;
  				end
  			end
			else begin
				core_index <= 32'd0;
				state <= COMPUTE;
  			end
  		end
  		else if (state == COMPUTE) begin
  			if(core_index < NUM_OF_CORES) begin
  				start_reg[core_index] <= 32'd2;
  				core_index <= core_index + 32'd1;
  			end
  			else begin
  				core_index <= 32'd0;
  				state <= WAIT_COMPUTE;
  			end
  		end
  		else if (state == WAIT_COMPUTE) begin
  			if(core_index < NUM_OF_CORES) begin
  				if(done[core_index] != 32'd2) begin
  					core_index <= core_index;
  					state <= WAIT_COMPUTE;
  				end
  				else begin
  					core_index <= core_index + 32'd1;
  					state <= WAIT_COMPUTE;
  				end
  			end
  			else begin
  				core_index <= 32'd0;
  				state <= STORE_DATA;
  			end
  		end
		if (state == STORE_DATA) begin
			if(core_index < NUM_OF_CORES) begin
				start_reg[core_index] <= 32'd3;
				state <= WAIT_STORE;
			end
			else begin
				core_index <= 32'd0;
				state <= DONE;
			end
		end
		else if (state == WAIT_STORE) begin
			if(core_index < NUM_OF_CORES) begin
				if(done[core_index] != 32'hFF) begin
					core_index <= core_index;
					state <= WAIT_STORE;
				end
				else begin
					start_reg[core_index] <= 32'd0;
					state <= STORE_DATA;
					core_index <= core_index + 32'd1;
				end
			end
			else begin
				core_index <= 32'd0;
				state <= DONE;
			end
  		 end
  		 else if (state == DONE) begin
  		 	all_done_reg <= 32'hFF;
  		 end
  	end
  end
  
always @ (posedge clk)
begin
	case (core_index)
	0: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[0];
			addr <= Addr_A[0];
			din <= WrData_A[0];
		end
	end
	1: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[1];
			addr <= Addr_A[1];
			din <= WrData_A[1];
		end
	end
	2: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[2];
			addr <= Addr_A[2];
			din <= WrData_A[2];
		end
	end
	3: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[3];
			addr <= Addr_A[3];
			din <= WrData_A[3];
		end
	end
	4: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[4];
			addr <= Addr_A[4];
			din <= WrData_A[4];
		end
	end
	5: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[5];
			addr <= Addr_A[5];
			din <= WrData_A[5];
		end
	end
	6: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[6];
			addr <= Addr_A[6];
			din <= WrData_A[6];
		end
	end
	7: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[7];
			addr <= Addr_A[7];
			din <= WrData_A[7];
		end
	end
	8: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[8];
			addr <= Addr_A[8];
			din <= WrData_A[8];
		end
	end
	9: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[9];
			addr <= Addr_A[9];
			din <= WrData_A[9];
		end
	end
	10: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[10];
			addr <= Addr_A[10];
			din <= WrData_A[10];
		end
	end
	11: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[11];
			addr <= Addr_A[11];
			din <= WrData_A[11];
		end
	end
	12: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[12];
			addr <= Addr_A[12];
			din <= WrData_A[12];
		end
	end
	13: begin
		if(start_reg[core_index] == 32'd1 || start_reg[core_index] == 32'd3) begin
			we <= WE_A[13];
			addr <= Addr_A[13];
			din <= WrData_A[13];
		end
	end
	endcase
end

endmodule
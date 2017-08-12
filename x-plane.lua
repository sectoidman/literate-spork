xplane_proto = Proto("x-plane","X-Plane UDP Data Protocol")

local vs_index_num = {
    [0] = "Frame Rate",
    [1] = "Times",
    [2] = "Sim Stats",
    [3] = "Airspeed",
    [4] = "G loads",
    [5] = "Weather",
    [6] = "Aircraft atmosphere",
    [7] = "System pressures",
    [8] = "Joystick aileron/elevator/rudder",
    [9] = "Other flight controls",
    [10] = "Artificial Stability",
    [11] = "Flight controls aileron/elevator/rudder",
    [12] = "Wing sweep and thrust vectoring",
    [13] = "Trim, flap, slats and speedbrakes",
    [14] = "Gear and Brakes",
    [15] = "Angular Moments",
    [16] = "Angular Velocities",
    [17] = "Attitude",
    [18] = "AOA",
    [19] = "Compass",
    [20] = "Global Position",
    [21] = "Sim Position",
    [22] = "All planes latitude",
    [23] = "All planes longitude",
    [24] = "All planes altitude",
    [25] = "Throttle command",
    [26] = "Throttle actual",
    [27] = "Engine feather, normal, beta and reverse",
    [28] = "Prop setting",
    [29] = "Mixture setting",
    [30] = "Carb heat",
    [31] = "Cowl flaps",
    [32] = "Magnetos",
    [33] = "Starter timeout",
    [34] = "Engine power",
    [35] = "Engine thrust",
    [36] = "Engine torque",
    [37] = "Engine RPM",
    [38] = "Propeller RPM",
    [39] = "Propeller Pitch",
    [40] = "Engine Wash",
    [41] = "N1",
    [42] = "N2",
    [43] = "Manifold pressure",
    [44] = "EPR",
    [45] = "Fuel Flow",
    [46] = "ITT",
    [47] = "EGT",
    [48] = "CHT",
    [49] = "Oil pressure",
    [50] = "Oil temperature",
    [51] = "Fuel pressure",
    [52] = "Generator amps",
    [53] = "Battery amps",
    [54] = "Battery volts",
    [55] = "Electric fuel pump on/off",
    [56] = "Idle speed low/high",
    [57] = "Battery on/off",
    [58] = "Generator on/off",
    [59] = "Inverter on/off",
    [60] = "FADEC on/off",
    [61] = "Igniter on/off",
    [62] = "Fuel weights",
    [63] = "Payload weights and CoG",
    [64] = "Aerodynamic force",
    [65] = "Engine force",
    [66] = "Landing gear vertical force",
    [67] = "Landing gear deployment",
    [68] = "Lift over drag and coefficients",
    [69] = "Prop efficiency",
    [70] = "Aileron deflections 1",
    [71] = "Aileron deflections 2",
    [72] = "Roll spoiler deflections 1",
    [73] = "Roll spoiler deflections 2",
    [74] = "Elevator deflections",
    [75] = "Rudder deflections",
    [76] = "Yaw and brake deflections",
    [77] = "Control forces",
    [78] = "Total vertical thrust vectors",
    [79] = "Total lateral thrust vectors",
    [80] = "Pitch cyclic disc tilts",
    [81] = "Roll cyclic disc tilts",
    [82] = "Pitch cyclic flapping",
    [83] = "Roll cyclic flapping",
    [84] = "Wing ground effect lift",
    [85] = "Wing ground effect drag",
    [86] = "Wing ground effect wash",
    [87] = "Stabilizer ground effect lift",
    [88] = "Stabilizer ground effect drag",
    [89] = "Stabilizer ground effect wash",
    [90] = "Propeller ground effect lift",
    [91] = "Propeller ground effect drag",
    [92] = "Wing lift",
    [93] = "Wing drag",
    [94] = "Stabilizer lift",
    [95] = "Stabilizer drag",
    [96] = "COM1 and COM2 radio freqs",
    [97] = "NAV1 and NAV2 radio freqs",
    [98] = "NAV1 and NAV2 OBS",
    [99] = "NAV1 deflection",
    [100] = "NAV2 deflection",
    [101] = "ADF1 and ADF2 statuses",
    [102] = "DME status",
    [103] = "GPS tatus",
    [104] = "Xpdr status",
    [105] = "Marker staus",
    [106] = "Electrical switches",
    [107] = "EFIS switches",
    [108] = "AP, FD, HUD switches",
    [109] = "Anti-ice switches",
    [110] = "Anti-ice and fuel switches",
    [111] = "Clutch and artificial stability switches",
    [112] = "Misc switches",
    [113] = "Gen. Annunciations 1",
    [114] = "Gen. Annunciations 2",
    [115] = "Engine annunciations",
    [116] = "Autopilot armed status",
    [117] = "Autopilot modes",
    [118] = "Autopilot values",
    [119] = "Weapon status",
    [120] = "Pressurization status",
    [121] = "APU and GPU status",
    [122] = "Radar status",
    [123] = "Hydraulic status",
    [124] = "Electrical and solar systems",
    [125] = "Icing status 1",
    [126] = "Icing status 2",
    [127] = "Warning status",
    [128] = "Flight plan legs",
    [129] = "Hardware options",
    [130] = "Camera location",
    [131] = "Ground location",
    [132] = "Climb stats",
    [133] = "Cruise stats",
    [134] = "Landing gear steering",
    [135] = "Motion platform stats"
}

-- Processes 'DATA' packets from X-Plane 11
-- Formatted as follows:
-- 4 byte packet type string
-- 1 byte 'internal use'
-- 14x 36 byte messages
-- -- 4 byte index number
-- -- 8x 4 byte single-precision floats
function xplane_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "X-PLANE"
    local subtree = tree:add(xplane_proto,buffer(),"X-Plane Protocol Data")
    subtree:add(buffer(0,4),"Packet Type: " .. buffer(0,4):string())
    subtree:add(buffer(4,1),
                "Internal Use Byte: " .. buffer(4,1):bytes():tohex())
    subtree:add(buffer(5), "Length: " .. buffer:len())

    -- Too lazy to implement processing for non-data packet types
    -- right now.
    if (buffer(0,4):string() ~= "DATA") then
        return
    end

    subtree = subtree:add(buffer(5),"Messages")
    for i=5,buffer:len()-1,36 do

        local d_idx = buffer(i,4):le_uint()
        local d_str = vs_index_num[d_idx]
        if d_str == nil then
            d_str = "Unknown - " .. d_idx
        end

        local branch = subtree:add(buffer(i,36), d_str)

        for j=i+4,i+32,4 do
            local d_value = buffer(j, 4):le_float()
            if (d_value ~= -999) then -- "-999" indicates padding / unused
                branch:add(buffer(j,4),
                           "Data: " .. d_value)
            end
        end
    end
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 49000
udp_table:add(49000,xplane_proto)

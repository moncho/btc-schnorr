package schnorr

import "testing"

func TestGuessPrivateKey(t *testing.T) {
	type args struct {
		publicKey string
		msg1      string
		sig1      string
		msg2      string
		sig2      string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Test 1",
			args: args{
				publicKey: "463F9E1F3808CEDF5BB282427ECD1BFE8FC759BC6F65A42C90AA197EFC6F9F26",
				msg1:      "6368616E63656C6C6F72206F6E20746865206272696E6B206F66207365636F6E",
				sig1:      "F3F148DBF94B1BCAEE1896306141F319729DCCA9451617D4B529EB22C2FB521A32A1DB8D2669A00AFE7BE97AF8C355CCF2B49B9938B9E451A5C231A45993D920",
				msg2:      "6974206D69676874206D616B652073656E7365206A75737420746F2067657420",
				sig2:      "F3F148DBF94B1BCAEE1896306141F319729DCCA9451617D4B529EB22C2FB521A974240A9A9403996CA01A06A3BC8F0D7B71D87FB510E897FF3EC5BF347E5C5C1",
			},
			want:    "congratulations you found the sk",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GuessPrivateKey(tt.args.publicKey, tt.args.msg1, tt.args.sig1, tt.args.msg2, tt.args.sig2)
			if (err != nil) != tt.wantErr {
				t.Errorf("GuessPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GuessPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

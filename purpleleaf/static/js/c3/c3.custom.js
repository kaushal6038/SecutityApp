// C3 Chart 1

$(document).ready(function() {
    $.ajax({
        type: "GET",
        async: false,
        url: "/api/charts/encryption",
        success: function(response) {
        	secure_sh_ciphers = response.data.secure_sh_ciphers;
        	ciphers = response.data.ciphers_proto;
			secure_ly_v2 = ciphers.secure_ly_v2;
			secure_ly_v3 = ciphers.secure_ly_v3;
			transport_ly_v1 = ciphers.transport_ly_v1;
			transport_ly_v1_1 = ciphers.transport_ly_v1_1;
			transport_ly_v1_2 = ciphers.transport_ly_v1_2;
			transport_ly_v1_3 = ciphers.transport_ly_v1_3;
			low_strength_count = response.data.cipher_strength.low_count;
			medium_strength_count = response.data.cipher_strength.medium_count;
			high_strength_count = response.data.cipher_strength.high_count;
        }
    });
    // sparkline Graphs

	$(function(){
		$("#pieGraph_protocol").sparkline(
				[
					secure_ly_v2,secure_ly_v3,
					transport_ly_v1,transport_ly_v1_1,
					transport_ly_v1_2,transport_ly_v1_3
				], {
			type: 'pie',
			width: '100',
			height: '100',
			sliceColors: ['#A1665F','#A1665F','#b5925a','#8a8c59','#8a8c59','#8a8c59'],
			text: ['SSLv2','SSLv3','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3']
		});
	});

	$(function(){
		$("#pieGraph_cipher").sparkline([low_strength_count,
				medium_strength_count,high_strength_count], {
			type: 'pie',
			width: '100',
			height: '100',
			sliceColors: ["#A1665F","#D9A66D","#8a8c59"],
			text:['low','medium','high']
		});
	});

	$(function(){
		$("#pieGraph_ssh").sparkline([secure_sh_ciphers], {
			type: 'pie',
			width: '100',
			height: '100',
			sliceColors: ['#BF7A6A']
		});
	});    
});

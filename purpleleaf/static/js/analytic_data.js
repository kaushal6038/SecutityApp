$(document).ready(function(){
    $.ajax({
    url: "/api/analytics",
    dataType: 'json',
    success: function(response){
        $.each(response, function (i, item){
            if (i=="firewall_data"){
                $('#text_firewall').text(item.description);
                if(item.risk == "Requires action") {
                    $('#risk_firewall').addClass('btn btn-danger');
                    $('#risk_firewall').text(item.risk);
                }
                else if(item.risk == "Potential risk") {
                    $('#risk_firewall').addClass('btn btn-warning');
                    $('#risk_firewall').text(item.risk);
                }
                else if(item.risk == "No issues identified") {
                    $('#risk_firewall').addClass('btn btn-success');
                    $('#risk_firewall').text(item.risk);
                }
                else if(item.risk == "Above average") {
                    $('#risk_firewall').addClass('btn btn-info');
                    $('#risk_firewall').text(item.risk);
                }
            }
            if (i=="encryption_analysis_data"){
                $('#text_Encryption_Analysis').text(item.description);
                if(item.risk == "Requires action") {
                    $('#risk_Encryption_Analysis').addClass('btn btn-danger');
                    $('#risk_Encryption_Analysis').text(item.risk);
                }
                else if(item.risk == "Potential risk") {
                    $('#risk_Encryption_Analysis').addClass('btn btn-warning');
                    $('#risk_Encryption_Analysis').text(item.risk);
                }
                else if(item.risk == "No issues identified") {
                    $('#risk_Encryption_Analysis').addClass('btn btn-success');
                    $('#risk_Encryption_Analysis').text(item.risk);
                }
                else if(item.risk == "Above average") {
                    $('#risk_Encryption_Analysis').addClass('btn btn-info');
                    $('#risk_Encryption_Analysis').text(item.risk);
                }
            }
            if (i=="exposure_analysis_data"){
                $('#text_Exposure_Analysis').text(item.description);
                if(item.risk == "Requires action") {
                    $('#risk_Exposure_Analysis').addClass('btn btn-danger');
                    $('#risk_Exposure_Analysis').text(item.risk);
                }
                else if(item.risk == "Potential risk") {
                    $('#risk_Exposure_Analysis').addClass('btn btn-warning');
                    $('#risk_Exposure_Analysis').text(item.risk);
                }
                else if(item.risk == "No issues identified") {
                    $('#risk_Exposure_Analysis').addClass('btn btn-success');
                    $('#risk_Exposure_Analysis').text(item.risk);
                }
                else if (item.risk == "Above average") {
                    $('#risk_Exposure_Analysis').addClass('btn btn-info');
                    $('#risk_Exposure_Analysis').text(item.risk);
                }
            }
        });
    }});
});
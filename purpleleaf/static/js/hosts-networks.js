function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

$.ajaxPrefilter(function(options, originalOptions, jqXHR){
    if (options['type'].toLowerCase() === "post") {
        jqXHR.setRequestHeader('X-CSRFToken', getCookie('csrftoken'));
    }
});

function createNetworkTable(){
    $.ajax({
        url: 'network/',
        type: 'GET',
        dataType: 'json',
        success: function(data){
            if (data.length >= 0){
                $('#network-table').html('');
                $('#network_dropdown_value').html('');
                $('#select-network').html('');
                $('#network_dropdown_value').append('<option id="" value="">----------</option>');
                $('#select-network').append('<option value="">--- Select Network ---</option>');
                var network_ids = [];
                var network_list = [];
                $.each(data, function (i, item){
                    network_ids.push(item.id);
                    network_data = {}
                    network_data.network = item.network;
                    network_data.id = item.id;
                    network_list.push(network_data);
                });
                var network_sorted_data = network_list.sort(function (a, b) {
                   return a.network.localeCompare( b.network );
                });
                var fisrt_net_id = network_ids.sort(function(a, b){return a-b})[0];
                $.each(data, function (i, item){
                    var counter = parseInt(i);
                    var count = counter+1;
                    var counter_td = '<td class="net_count_width">' + count + '</td>'
                    var critical_button = '<button class="btn btn-critical-count btn-xs">' + item.vulnerabilities.critical + '</button>';
                    var high_button = '&nbsp;<button class="btn btn-high-count btn-xs">' + item.vulnerabilities.high + '</button>'
                    var medium_button = '&nbsp;<button class="btn btn-medium-count btn-xs">' + item.vulnerabilities.medium + '</button>'
                    var low_button = '&nbsp;<button class="btn btn-low-count btn-xs">' + item.vulnerabilities.low + '</button></td>'
                    var vulnerabilities_td = '<td>' + critical_button + high_button + medium_button + low_button + '</td>'
                    var network_td = '<td><label id="network-label-'+ item.id + '">' + item.network + '</label></td>'
                    if (item.network_type) {
                        var network_type = item.network_type;
                    }
                    else {
                        var network_type = "N/A";
                    }
                    var network_type_td = '<td id="change-network-type-'+ item.id + '"><center>' + network_type + '</center></td>'
                    var ips_td = '<td><center>' +item.vulnerabilities.host_count + '</center></td>'
                    var network_edit_btn = '<a id="edit_net_name_' +item.id+ '" onclick="edit_network_name('+ item.id + ',\'' + item.network + '\',\'' +item.network_type + '\');"><span class="icon-edit"></span></a>'
                    var ntwrk_dlt_btn = '&nbsp;<a onclick="delete_network(' + item.id + ');"><span class="icon-bin"></span></a>'
                    if (item.id == fisrt_net_id){
                        var action_td = '<td><center>' + network_edit_btn + '</center></td>';
                    }
                    else{
                        var action_td = '<td><center>' + network_edit_btn + ntwrk_dlt_btn + '</center></td>';
                    }
                    var full_tr = '<tr id="network_tr_' + item.id + '">' + counter_td + vulnerabilities_td + network_td + network_type_td + ips_td + action_td + '</tr>'
                    $('#network-table').append(full_tr);
                    $('#network_dropdown_value').append('<option id="select_network_'+ item.id +'" value="'+ item.id +'">' + item.network + '</option>');
                });
                $.each(network_sorted_data, function (i, item){
                    $('#select-network').append('<option value="' + item.id + '">' + item.network +'</option>');
                })
            }
            // generate_host_network_update_dropdown();
            generate_host_network_add_dropdown();
        }
    });
}

function addNetwork(){
    var hostregex = /^[0-9a-zA-Z_ -]+$/;
    var network = $('#network_input_id').val();
    var network_type = $('#network_type').val();
    if (network && network.match(hostregex)) {
        if (network_type) {
            $.ajax({
                url: 'network/',
                type: 'POST',
                data: {
                    'network': network,
                    'network_type': network_type,
                    },
                success: function(response) {
                    if (response.status == true){
                        UpdateHostsCount();
                        // $('#network_dropdown_value').append('<option id="select_network_'+ response.data.id +'" value="'+response.data.id+'">'+network+'</option>');
                        // $('.host-network-add').append('<option value="'+response.data.id+'">'+network+'</option>');
                        // edit_host_network_parent = $('.edit-host-network-select').find('.select-items');
                        // host_network_parent = $('.host-network-select').find('.select-items');
                        // edit_host_network_parent.append('<div>' + network + '</div>')
                        // host_network_parent.append('<div class="same-as-selected">' + network + '</div>')
                        $.growl.notice({
                            title:"Success",
                            message: "Network added successfully!"
                        });
                        $('#network_input_id').val("");
                    }
                    else if(response.status == false){
                        if (response.status_code == 400){
                            $.growl.error({
                                title: response.message,
                                message: response.errors.non_field_errors
                            });
                        }
                        else {
                            $.growl.error({
                                title:"Error", 
                                message: response.message 
                            });
                        }
                    }
                    createNetworkTable();
                }

                });
            }
        else {
            $.growl.error({title:"Alert", message: "Please select network type" });
        }
    }
    else if(network && network.match(hostregex)!=true){
        $.growl.error({title:"Alert", message: "Network names may only contain letters, numbers, and spaces" });
    }
    else{
        $.growl.error({title:"Alert", message: "Please enter network" });
    }
}

function delete_network(network_id){
    $.ajax({
        url: 'network/' + network_id + "/",
        type: 'GET',
        success: function(response){
            if (response.status == true){
                var host_count = (response.data.vulnerabilities.host_count);
                var vul_count = (response.data.vulnerabilities.count);
                alertify.confirm((host_count+","+vul_count), function (e) {
                    if(e){
                        $.ajax({
                            url: 'network/' + network_id + "/",
                            type: "DELETE",
                            dataType: 'json',
                            success: function(response){
                                if (response.status == true){
                                    UpdateHostsCount();
                                    $('#select_network_'+network_id).remove();
                                    $('#host_tr_'+network_id).remove();
                                    var selectobject = document.getElementById("select-network");
                                    for (var i=0; i<selectobject.length; i++){
                                        if (selectobject.options[i].value == network_id ){
                                            selectobject.remove(i);
                                        }
                                    }
                                    var selectnetworkobject = document.getElementById("network_dropdown_value");
                                    for (var i=0; i<selectnetworkobject.length; i++){
                                        if (selectnetworkobject.options[i].value == network_id ){
                                            selectnetworkobject.remove(i);
                                        }
                                    }
                                    $.growl.notice({title:"Success", message: response.message });
                                    createNetworkTable();
                                }
                                else {
                                    $.growl.error({title:"Oops!", message: response.message });
                               }
                            },
                            error:function (xhr, ajaxOptions, thrownError){
                                $.growl.error({title:"Oops!", message: thrownError });
                            }
                        });
                    }
                });
            }
            else {
                $.growl.error({title:"Oops!", message: response.message });
           }
        },
        error:function (xhr, ajaxOptions, thrownError){
            $.growl.error({title:"Oops!", message: thrownError });
        }
    });
}



function host_network_update(host_id,network){
    $('#edit_host_network_id').val(host_id);    var selected_network = "#network_dropdown_value option[value='" + network + "']";
    $(selected_network).attr("selected",true);
    $('#hostnetworkModal').modal('show');
    generate_host_network_update_dropdown();
};


function update_host_network(){
    var network_id = $('#network_dropdown_value').val();
    var network_name = $('#network_dropdown_value').find("option:selected").text();
    var host_id = $('#edit_host_network_id').val();
    var lable_id;
    $.ajax({
        url: '/host-network-update/',
        type: 'PATCH',
        data: {
            'network_id': network_id,
            'host_id': host_id
            },
        dataType: 'json',
        success: function(response){
            if (response.status == true){
                $.growl.notice(
                    {
                        title:"Success",
                        message: response.message
                    }
                );
                $('#hostnetworkModal').modal('hide');
                createHostTable();
                // network_type_label_id = "#hosts_network_type_"+host_id;
                // lable_id = "#label-"+host_id;
                // $(lable_id).text(network_name);
                // $(network_type_label_id).text(response.data.network_type);
            }
            else if (response.status == false){
                if (response.status_code == 400){
                    if (response.errors.non_field_errors){
                        var message = response.errors.non_field_errors;
                    }
                    else if (response.errors){
                        var message = response.errors;
                    }
                    $.growl.error(
                        {
                            title: response.message,
                            message: message
                        }
                    );
                }
                else{
                    $.growl.error(
                        {
                            title: "Error " + response.status_code,
                            message: response.message
                        }
                    );
                }
            }
            else {
                $.growl.error({title:"Error!", message: "Unable to update Network" });
            }
        }
    });
}


function edit_network_name(network_id, network_name, network_type){
    $('.edit_network_div').find('.select-selected').text(network_type);
    var selected_network = "#change_network_type option[value='" + network_type + "']";
    $(selected_network).attr("selected",true);
    $('#network_name_id').val(network_name);
    $('#hidden_network_name_id').val(network_id);
    $('#editNetworkModal').modal('show');
}


function save_edit_network_name(){
    network_name = $('#network_name_id').val();
    network_id = $('#hidden_network_name_id').val();
    network_type = $('#change_network_type').val();
    $.ajax({
        url: 'network/' + network_id + "/",
        type: 'PATCH',
        data: {
            'network_name': network_name,
            'network_type':network_type
            },
        dataType: 'json',
        success: function(response){
            if (response.status == true){
                 $.growl.notice(
                    {
                        title:"Success",
                        message: response.message
                    }
                );
                network_label_id = "#network-label-"+network_id;
                $(network_label_id).text(network_name);
                $('#edit_net_name_'+network_id).attr("onclick","edit_network_name("+network_id+",'"+network_name+"')");
                $('#select_network_'+network_id).text(network_name);
                $('#network_name_id').val(network_name);
                net_id = '#change-network-type-'+network_id;
                $(net_id).text(network_type);
                $(net_id).css('text-align','center');
                $('.network_label_class_'+network_id).text(network_name);
                $('#editNetworkModal').modal('hide');
            }
            else if (response.status == false){
                if (response.status_code == 400){
                    $.growl.error(
                        {
                            title: response.message,
                            message: response.errors.non_field_errors
                        }
                    );
                }
                else{
                    $.growl.error(
                        {
                            title: "Error " + response.status_code,
                            message: response.message
                        }
                    );
                }
            }
            else {
                $.growl.error({title:"Error!", message: "Unable to update Network" });
           }
        }
    });
}

var myVar;

function showClipboard(id) {
    clearTimeout(myVar);
    // $('.tooltips').hide();
    $('.tooltips').fadeOut(500);
    tooltip_id = "#tool-tip-" + id;
    //$(tooltip_id).show();
    $(tooltip_id).stop(true).hide().fadeIn(800);
}



function hideClipboard(id) {
    tooltip_hide_id = "#tool-tip-" + id;
    myVar = setTimeout(function() {
        $(tooltip_hide_id).fadeOut();
        // $(tooltip_hide_id).fadeOut("slow");
        $(tooltip_hide_id).fadeOut(600);
        // $(tooltip_hide_id).hide();
    }, 300);
}

function hideLabelClipboard(id){
    $('.tooltips').fadeOut(600);
}

function clipboardOutFunc(id) {
    clearTimeout(myVar);
    var myTooltip = "myTooltip-"+id;
    var tooltip = document.getElementById(myTooltip);
    tooltip.innerHTML = "Copy to clipboard";
    tooltip_hide_id = "#tool-tip-" + id;
    myVar = setTimeout(function() {
        $('.tooltips').fadeOut(600);
        $(tooltip_hide_id).fadeOut();
        $(tooltip_hide_id).fadeOut("slow");
        $(tooltip_hide_id).fadeOut(600);
        // $(tooltip_hide_id).hide();
    }, 300);
}

function VisibleClipboard(id) {
    clearTimeout(myVar);
}

function copyToClipboard(id) {
    var myTooltip = "myTooltip-"+id;
    var input_id = "#myInput-" + id;
    var tooltip = document.getElementById(myTooltip);
    tooltip.innerHTML = "Copy to clipboard";

    var aux = document.createElement("input");

    // Get the text from the element passed into the input
    var text_to_copy = $(input_id).val();
    aux.setAttribute("value", text_to_copy);

    // Append the aux input to the body
    document.body.appendChild(aux);

    // Highlight the content
    aux.select();

    // Execute the copy command
    document.execCommand("copy");

    // Remove the input from the body
    document.body.removeChild(aux);

    var tooltip = document.getElementById(myTooltip);

    tooltip.innerHTML = "Copied!";
}

function createHostTable(){
    $.ajax({
        url: 'host/',
        type: 'GET',
        dataType: 'json',
        success: function(response){
            var external_host_data = response.external_host_data;
            var internal_host_data = response.internal_host_data;
            if (external_host_data.length > 0 || internal_host_data.length > 0 ){
                $('.external_host_table_container').show();
            }
            else{
                $('.external_host_table_container').hide();
            }
            if (external_host_data.length == 0){
                $('#external_host_label').html('');
            }
            if (external_host_data.length > 0){
                $('#internal_host_label').addClass('internal_host_label_margin');
                $('#external_host_table').html('');
                $('#external_host_label').html('External Hosts');
                $.each(external_host_data, function (i, item){
                    var checkbox_label = '<label class="host-delete-label">'
                    var checkbox_input = '<input type="checkbox" name="customer_id[]" class="checkbox" value="' + external_host_data[i].id + '">'
                    var checkbox_span = '<span class="host-delete-checkmark"></span>'
                    var checkbox_td = '<td>' + checkbox_label + checkbox_input + checkbox_span +'</td>'
                    if (external_host_data[i].host_type == "cidr"){
                        var host_button_td = '<td onmouseout="hideLabelClipboard('
                        + external_host_data[i].id 
                        + ')" onmouseover="showClipboard('
                        + external_host_data[i].id
                        + ')"><input type="hidden" value="'
                        + external_host_data[i].host
                        + '" id="myInput-'
                        + external_host_data[i].id 
                        + '"><button onmouseout="hideClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseover="showClipboard(' 
                        + external_host_data[i].id 
                        + ')" class="host-button" id="' 
                        + external_host_data[i].id 
                        + '" onclick="javascript:IpTrackInfo(this)">' 
                        + external_host_data[i].host 
                        + '</button><label style="width:9px; margin-bottom:0px;"><p class="tooltips" id="tool-tip-' 
                        + external_host_data[i].id 
                        + '"><button class="clipboard-icon-style" onmouseover="VisibleClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseout="clipboardOutFunc(' 
                        + external_host_data[i].id 
                        + ')" onclick="copyToClipboard(' 
                        + external_host_data[i].id 
                        + ')"><span class="tooltiptext" id="myTooltip-' 
                        + external_host_data[i].id 
                        + '">Copy to clipboard</span><i style="margin-left:-8px;" class="fas fa-copy"></i></button></p></label>&nbsp;&nbsp;</td>'
                    }
                    else if (external_host_data[i].host_type == "loose_a"){
                        var host_button_td = '<td onmouseout="hideLabelClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseover="showClipboard(' 
                        + external_host_data[i].id 
                        + ')"><input type="hidden" value="' 
                        + external_host_data[i].host 
                        + '" id="myInput-' 
                        + external_host_data[i].id 
                        + '"><button onmouseout="hideClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseover="showClipboard(' 
                        + external_host_data[i].id 
                        + ')" class="host-button" id="' 
                        + external_host_data[i].id 
                        + '" onclick="javascript:IpTrackInfo(this)">' 
                        + external_host_data[i].host 
                        + '</button><label style="width:9px; margin-bottom:0px;"><p class="tooltips" id="tool-tip-' 
                        + external_host_data[i].id 
                        + '"><button class="clipboard-icon-style" onmouseover="VisibleClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseout="clipboardOutFunc(' 
                        + external_host_data[i].id 
                        + ')" onclick="copyToClipboard(' 
                        + external_host_data[i].id 
                        + ')"><span class="tooltiptext" id="myTooltip-' 
                        + external_host_data[i].id 
                        + '">Copy to clipboard</span><i style="margin-left:-8px;" class="fas fa-copy"></i></button></p></label>&nbsp;&nbsp;</td>'
                    }
                    else if (external_host_data[i].host_type == "loose_b"){
                        var host_button_td = '<td onmouseout="hideLabelClipboard('
                        + external_host_data[i].id
                        + ')" onmouseover="showClipboard('
                        + external_host_data[i].id
                        + ')"><input type="hidden" value="' 
                        + external_host_data[i].host 
                        + '" id="myInput-' 
                        + external_host_data[i].id 
                        + '"><button onmouseout="hideClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseover="showClipboard(' 
                        + external_host_data[i].id 
                        + ')" class="host-button" id="' 
                        + external_host_data[i].id 
                        + '" onclick="javascript:IpTrackInfo(this)">' 
                        + external_host_data[i].host 
                        + '</button><label style="width:9px; margin-bottom:0px;"><p class="tooltips" id="tool-tip-' 
                        + external_host_data[i].id 
                        + '"><button class="clipboard-icon-style" onmouseover="VisibleClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseout="clipboardOutFunc(' 
                        + external_host_data[i].id 
                        + ')" onclick="copyToClipboard(' 
                        + external_host_data[i].id 
                        + ')"><span class="tooltiptext" id="myTooltip-' 
                        + external_host_data[i].id 
                        + '">Copy to clipboard</span><i style="margin-left:-8px;" class="fas fa-copy"></i></button></p></label>&nbsp;&nbsp;</td>'
                    }
                    else{
                        var host_button_td = '<td onmouseout="hideLabelClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseover="showClipboard(' 
                        + external_host_data[i].id 
                        + ')"><input type="hidden" value="' 
                        + external_host_data[i].host 
                        + '" id="myInput-' 
                        + external_host_data[i].id 
                        + '"><a href="/host/'
                        + external_host_data[i].host_id 
                        +'/"><button onmouseout="hideClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseover="showClipboard(' 
                        + external_host_data[i].id 
                        + ')" class="host-button" id="' 
                        + external_host_data[i].id 
                        + '" onclick="javascript:IpTrackInfo(this)">' 
                        + external_host_data[i].host 
                        + '</button></a><label style="width:9px; margin-bottom:0px;"><p class="tooltips" id="tool-tip-' 
                        + external_host_data[i].id 
                        + '"><button class="clipboard-icon-style" onmouseover="VisibleClipboard(' 
                        + external_host_data[i].id 
                        + ')" onmouseout="clipboardOutFunc(' 
                        + external_host_data[i].id 
                        + ')" onclick="copyToClipboard(' 
                        + external_host_data[i].id 
                        + ')"><span class="tooltiptext" id="myTooltip-' 
                        + external_host_data[i].id 
                        + '">Copy to clipboard</span><i style="margin-left:-8px;" class="fas fa-copy"></i></button></p></label>&nbsp;&nbsp;</td>'
                    }
                    var host_delete_button = '<td><button class="host-button" id="' + external_host_data[i].id + '" onclick="javascript:RemoveHost(this)"><span class="icon-bin"></span></button></td>'
                    if (external_host_data[i].network.network){
                        if(external_host_data[i].network.network == "AWS"){
                            var aws_button = '<button class="btn btn-success btn-transparent btn-xs aws_button_green">aws</button>';
                            host_delete_button = '';
                        }else{
                            var aws_button = '';
                        }
                        var host_network_td = '<td><label style="margin-left:-2px;" id="label-' + external_host_data[i].id + '" class="network_label_class_' + external_host_data[i].network.id +' host_network_margin">' +  external_host_data[i].network.network + '</label>'+aws_button+'&nbsp;&nbsp;</td>'
                        var host_network_update_td = '<td><a onclick="host_network_update(' + external_host_data[i].id + ',' + external_host_data[i].network.id + ');"><span class="icon-edit"></span></a>&nbsp;</td>'
                        if (external_host_data[i].host_type != 'ip'){
                            var iptrack_td = '<td><button class="host-button" id="' + external_host_data[i].id +'" onclick="javascript:IpTrackInfo(this)"><span style="float: right;" class="glyphicon glyphicon-menu-right"></span></button></td>'
                            var full_tr = '<tr id="host_tr_' + external_host_data[i].id + '">' + checkbox_td + host_button_td + host_network_td  + host_network_update_td + host_delete_button + iptrack_td + '</tr>'
                        }
                        else{
                            var full_tr = '<tr id="host_tr_' + external_host_data[i].id + '">' + checkbox_td + host_button_td +  host_network_td + host_network_update_td + host_delete_button +'</tr>'
                        }
                    }
                    else{
                        if (external_host_data[i].host_type != 'ip'){
                            var iptrack_td = '<td><button class="host-button" id="' + external_host_data[i].id +'" onclick="javascript:IpTrackInfo(this)"><span style="float: right;" class="glyphicon glyphicon-menu-right"></span></button></td>'
                            var full_tr = '<tr id="host_tr_' + external_host_data[i].id + '">' + checkbox_td + host_button_td + host_delete_button + iptrack_td + '</tr>'
                        }
                        else{
                            var full_tr = '<tr id="host_tr_' + external_host_data[i].id + '">' + checkbox_td + host_button_td +  host_delete_button + '</tr>'
                        }
                    }
                    $('#external_host_table').append(full_tr);
                    $('.tooltips').hide();
                })
            }
            else{
                $('#external_host_table').html('');
            }
            if (internal_host_data.length == 0){
                $('#internal_host_label').html('');
            }
            if (internal_host_data.length > 0){
                $('#internal_host_table').html('');
                $('#internal_host_label').html('Internal Hosts');
                $.each(internal_host_data, function (i, item){
                    var checkbox_label = '<label class="host-delete-label">'
                    var checkbox_input = '<input type="checkbox" name="customer_id[]" class="checkbox" value="' + internal_host_data[i].id + '">'
                    var checkbox_span = '<span class="host-delete-checkmark"></span>'
                    var checkbox_td = '<td>' + checkbox_label + checkbox_input + checkbox_span +'</td>'
                    if (internal_host_data[i].host_type == "cidr"){
                        var host_button_td = '<td onmouseout="hideLabelClipboard(' + internal_host_data[i].id + ')" onmouseover="showClipboard(' + internal_host_data[i].id + ')"><input type="hidden" value="' + internal_host_data[i].host + '" id="myInput-' + internal_host_data[i].id + '"><button onmouseout="hideClipboard(' + internal_host_data[i].id + ')" onmouseover="showClipboard(' + internal_host_data[i].id + ')" class="host-button" id="' + internal_host_data[i].id + '" onclick="javascript:Internal_IpTrackInfo(this)">' + internal_host_data[i].host + '</button><label style="width:9px; margin-bottom:0px;"><p class="tooltips" id="tool-tip-' + internal_host_data[i].id + '"><button class="clipboard-icon-style" onmouseover="VisibleClipboard(' + internal_host_data[i].id + ')" onmouseout="clipboardOutFunc(' + internal_host_data[i].id + ')" onclick="copyToClipboard(' + internal_host_data[i].id + ')"><span class="tooltiptext" id="myTooltip-' + internal_host_data[i].id + '">Copy to clipboard</span><i style="margin-left:-8px;" class="fas fa-copy"></i></button></p></label>&nbsp;&nbsp;</td>'
                    }
                    else if (internal_host_data[i].host_type == "loose_a"){
                        var host_button_td = '<td onmouseout="hideLabelClipboard(' + internal_host_data[i].id + ')" onmouseover="showClipboard(' + internal_host_data[i].id + ')"><input type="hidden" value="' + internal_host_data[i].host + '" id="myInput-' + internal_host_data[i].id + '"><button onmouseout="hideClipboard(' + internal_host_data[i].id + ')" onmouseover="showClipboard(' + internal_host_data[i].id + ')" class="host-button" id="' + internal_host_data[i].id + '" onclick="javascript:Internal_IpTrackInfo(this)">' + internal_host_data[i].host + '</button><label style="width:9px; margin-bottom:0px;"><p class="tooltips" id="tool-tip-' + internal_host_data[i].id + '"><button class="clipboard-icon-style" onmouseover="VisibleClipboard(' + internal_host_data[i].id + ')" onmouseout="clipboardOutFunc(' + internal_host_data[i].id + ')" onclick="copyToClipboard(' + internal_host_data[i].id + ')"><span class="tooltiptext" id="myTooltip-' + internal_host_data[i].id + '">Copy to clipboard</span><i style="margin-left:-8px;" class="fas fa-copy"></i></button></p></label>&nbsp;&nbsp;</td>'
                    }
                    else if (internal_host_data[i].host_type == "loose_b"){
                        var host_button_td = '<td onmouseout="hideLabelClipboard(' + internal_host_data[i].id + ')" onmouseover="showClipboard(' + internal_host_data[i].id + ')"><input type="hidden" value="' + internal_host_data[i].host + '" id="myInput-' + internal_host_data[i].id + '"><button onmouseout="hideClipboard(' + internal_host_data[i].id + ')" onmouseover="showClipboard(' + internal_host_data[i].id + ')" class="host-button" id="' + internal_host_data[i].id + '" onclick="javascript:Internal_IpTrackInfo(this)">' + internal_host_data[i].host + '</button><label style="width:9px; margin-bottom:0px;"><p class="tooltips" id="tool-tip-' + internal_host_data[i].id + '"><button class="clipboard-icon-style" onmouseover="VisibleClipboard(' + internal_host_data[i].id + ')" onmouseout="clipboardOutFunc(' + internal_host_data[i].id + ')" onclick="copyToClipboard(' + internal_host_data[i].id + ')"><span class="tooltiptext" id="myTooltip-' + internal_host_data[i].id + '">Copy to clipboard</span><i style="margin-left:-8px;" class="fas fa-copy"></i></button></p></label>&nbsp;&nbsp;</td>'
                    }
                    else{
                        var host_button_td = '<td onmouseout="hideLabelClipboard(' + internal_host_data[i].id + ')" onmouseover="showClipboard(' + internal_host_data[i].id + ')"><input type="hidden" value="' + internal_host_data[i].host + '" id="myInput-' + internal_host_data[i].id + '"><a href="/host/'+ internal_host_data[i].id +'/"><button onmouseout="hideClipboard(' + internal_host_data[i].id + ')" onmouseover="showClipboard(' + internal_host_data[i].id + ')" class="host-button" id="' + internal_host_data[i].id + '" onclick="javascript:Internal_IpTrackInfo(this)">' + internal_host_data[i].host + '</button></a><label style="width:9px; margin-bottom:0px;"><p class="tooltips" id="tool-tip-' + internal_host_data[i].id + '"><button class="clipboard-icon-style" onmouseover="VisibleClipboard(' + internal_host_data[i].id + ')" onmouseout="clipboardOutFunc(' + internal_host_data[i].id + ')" onclick="copyToClipboard(' + internal_host_data[i].id + ')"><span class="tooltiptext" id="myTooltip-' + internal_host_data[i].id + '">Copy to clipboard</span><i style="margin-left:-8px;" class="fas fa-copy"></i></button></p></label>&nbsp;&nbsp;</td>'
                    }
                    var host_delete_button = '<td><button class="host-button" id="' + internal_host_data[i].id + '" onclick="javascript:RemoveHost(this)"><span class="icon-bin"></span></button></td>'
                    if (internal_host_data[i].network.network){
                        if(internal_host_data[i].network.network == "AWS"){
                            var aws_button = '<button class="btn btn-success btn-transparent btn-xs aws_button_green">aws</button>';
                            host_delete_button = '';
                        }else{
                            var aws_button = '';
                        }
                        var host_network_td = '<td><label style="margin-left:-2px" id="label-' + internal_host_data[i].id + '" class="network_label_class_' + internal_host_data[i].network.id +' host_network_margin">' +  internal_host_data[i].network.network + '</label>'+aws_button+'&nbsp;&nbsp;</td>'
                        var host_network_update_td = '<td><a onclick="host_network_update(' + internal_host_data[i].id + ',' + internal_host_data[i].network.id + ');"><span class="icon-edit"></span></a>&nbsp;</td>'
                        if (internal_host_data[i].host_type != 'ip'){
                            var iptrack_td = '<td><button class="host-button" id="' + internal_host_data[i].id +'" onclick="javascript:Internal_IpTrackInfo(this)"><span style="float: right;" class="glyphicon glyphicon-menu-right"></span></button></td>'
                            var full_tr = '<tr id="host_tr_' + internal_host_data[i].id + '">' + checkbox_td + host_button_td + host_network_td + host_network_update_td + host_delete_button + iptrack_td + '</tr>'
                        }
                        else{
                            var full_tr = '<tr id="host_tr_' + internal_host_data[i].id + '">' + checkbox_td + host_button_td +  host_network_td + host_network_update_td + host_delete_button +'</tr>'
                        }
                    }
                    else{
                        if (internal_host_data[i].host_type != 'ip'){
                            var iptrack_td = '<td><button class="host-button" id="' + internal_host_data[i].id +'" onclick="javascript:Internal_IpTrackInfo(this)"><span style="float: right;" class="glyphicon glyphicon-menu-right"></span></button></td>'
                            var full_tr = '<tr id="host_tr_' + internal_host_data[i].id + '">' + checkbox_td + host_button_td + host_delete_button + iptrack_td + '</tr>'
                        }
                        else{
                            var full_tr = '<tr id="host_tr_' + internal_host_data[i].id + '">' + checkbox_td + host_button_td +  host_delete_button + '</tr>'
                        }
                    }
                    $('#internal_host_table').append(full_tr);
                    $('.tooltips').hide();
                })
            }
            else{
                $('#internal_host_table').html('');
            }
        }
    });
    createNetworkTable()
}

$(document).ready(function () {
    createHostTable();
});
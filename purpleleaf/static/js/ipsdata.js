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

var srcElement = $('#external_iptrackinfo')[0];
var ipstable = $('#external_iptrackinfo')[0];
function IpTrackInfo(obj)
    {
        var left = $("#external_host_table").width();
        console.log('left',left)
        var offset = $(obj).position();
        $('#external_iptrackinfo').html('');
        var top = offset.top;
        button = $(obj).attr("id")
        $.ajax({
            url: '/data/iptrackinfo/',
            type: 'POST',
            data: {
                'hostid': $(obj).attr("id")
                },
            dataType: 'json',
            success: function(data){
            if (data==""){
                $('.data_right').css("margin-top", (top) +'px');
                $('.data_right').css("margin-left", (left) +'px');
                $('.data_right').css("width",'100px;');
                // $('#iptrackinfo').append('<p>No Record.</p>');
            }
            else {
                $('.data_right').css("width",'125px');
                $('.data_right').css("height",'340px');
            $.each(data, function (i, item){
                $('.data_right').css("margin-top", (top-85) +'px');
                $('.data_right').css("margin-left", (left) +'px');
                $('#external_iptrackinfo').append('<tr><td>' + data[i].ip + '</td></tr>');   
                
            });
            }
            console.log('srcElement',srcElement)
                if (srcElement != null) {
                    if (srcElement.style.display == "block") {
                        srcElement.style.display = 'none';
                    }
                    else {
                        srcElement.style.display = 'block';
                        $('#external_iptrackinfo').show();
                    }
                    return false;
                }

           }
       });
    }

var intsrcElement = $('#internal_iptrackinfo')[0];
var ipstable = $('#internal_iptrackinfo')[0];
function Internal_IpTrackInfo(obj)
    {
        var left = $("#internal_host_table").width();
        console.log('left==',left)
        var offset = $(obj).position();
        $('#internal_iptrackinfo').html('');
        var top = offset.top;
        button = $(obj).attr("id")
        $.ajax({
            url: '/data/iptrackinfo/',
            type: 'POST',
            data: {
                'hostid': $(obj).attr("id")
                },
            dataType: 'json',
            success: function(data){
            if (data==""){
                $('.int_data_rights').css("margin-top", (top) +'px');
                $('.int_data_rights').css("margin-left", (left) +'px');
                $('.int_data_rights').css("width",'100px;');
                // $('#iptrackinfo').append('<p>No Record.</p>');
            }
            else {
                $('.int_data_rights').css("width",'125px');
                $('.int_data_rights').css("height",'340px');
                $('.int_data_rights').css("overflow",'auto');
            $.each(data, function (i, item){
                $('.int_data_rights').css("margin-top", (top-42) +'px');
                $('.int_data_rights').css("margin-left", (left+10) +'px');
                $('#internal_iptrackinfo').append('<tr><td>' + data[i].ip + '</td></tr>');   
            });
            }
            
                if (intsrcElement != null) {
                    if (intsrcElement.style.display == "block") {
                        intsrcElement.style.display = 'none';
                    }
                    else {
                        intsrcElement.style.display = 'block';
                        $('#internal_iptrackinfo').show();
                    }
                    return false;
                }

           }
       });
    }


$(document).on("click",function(e) {
   if ($(e.target).is(".tab-content *")){

       $("#external_iptrackinfo").hide();}

   else{
       $("#external_iptrackinfo").html('');
        }
});

$( document ).on( 'keydown', function ( e ) {
    if ( e.keyCode === 27 ) {
        $("#external_iptrackinfo").html('');
    }
});

$(document).click(function(e) {

  if( e.target.id != 'external_iptrackinfo') {
    $("#external_iptrackinfo *").hide();
  }
});


$(document).on("click",function(e) {
   if ($(e.target).is(".tab-content *")){       
       $("#internal_iptrackinfo").hide();}

   else{
       $("#internal_iptrackinfo").html('');
        }
});

$( document ).on( 'keydown', function ( e ) {
    if ( e.keyCode === 27 ) {
        $("#internal_iptrackinfo").html('');
    }
});

$(document).click(function(e) {

  if( e.target.id != 'internal_iptrackinfo') {
    $("#internal_iptrackinfo *").hide();
  }
});
   

function addDomain(){
    var domain_name = $('#domain_input_id').val();
    var network_type = $('#domain_network_type').val();
    if (domain_name) {
        $.ajax({
            url: 'domains/',
            type: 'POST',
            data: {
                'domain_name': domain_name,
                'network_type': network_type
            },
            success: function(response) {
                if (response.status == true){
                    UpdateHostsCount();
                    $.growl.notice({
                        title:"Success",
                        message: "Domain added successfully!"
                    });
                    $('#domain_input_id').val("");
                }
                else if(response.status == false){
                    if (response.status_code == 400){
                        $.growl.error({
                            title: response.message,
                            message: response.errors.domain_name
                        });
                    }
                    else {
                        $.growl.error({
                            title:"Error",
                            message: response.message
                        });
                    }
                }
                createDomainTable();
            }
        });
    }
    else{
        $.growl.warning({message: "Please Enter Domain Name" });
    }
}   


function removeCloudAsset(exclude_id)
{
    $.ajax({
        url: 'cloud-assets/' + exclude_id + "/",
        type: 'DELETE',
        success: function(response){

            if (response.status == true) {
                $.growl.notice({title:"Success", message: response.message});
                createCloudAssetTables();
            }
            else {
                $.growl.error({title:"Opps !", message: response.message });
                }
            },
        error:function (xhr, ajaxOptions, thrownError){
            $.growl.error({title:"Oops!", message: thrownError });
        }
     });
}

function removeAssetToken(token_id)
{
    $.ajax({
        url: '/api/aws-key-status/' + token_id,
        type: 'DELETE',
        success: function(response){

            if (response.status == true) {
                $.growl.notice({title:"Success", message: response.message});
                createCloudAssetTables();
            }
            else {
                $.growl.error({title:"Opps !", message: response.message });
                }
            },
        error:function (xhr, ajaxOptions, thrownError){
            $.growl.error({title:"Oops!", message: thrownError });
        }
     });
}


function removeCloudAssetButton(exclude_id)
    {
        return "<button class=\"close\" style=\"color:red;\"  onclick=\"removeCloudAsset(" + exclude_id  + ")\" aria-label=\"Close\"><span aria-hidden=\"true\">&nbsp;&times;</span></button>";
    };

function AssetTokenRemoveButton(exclude_id)
    {
        return "<button class=\"close\" style=\"color:red; margin-right:23px;\"  onclick=\"removeAssetToken(" + exclude_id  + ")\" aria-label=\"Close\"><span aria-hidden=\"true\">&nbsp;&times;</span></button>";
    };

function createCloudAssetTables(){
    $.ajax({
        type: "GET",
        async: false,
        url: 'cloud-assets/',
        success: function(response)
        {
            $('#id_category').val('S3');
            $('#id_bucket').val('');
            $('#s3').html('');
            $('#azure').html('');
            $('#gcp').html('');
            $('#aws-asset-table').html('');
            UpdateHostsCount();
            if (response.S3.length !==0) {
                $.each(response.S3, function (i, item){
                    if (item.bucket_type == "Unmanaged"){
                       var bucket_type_button = '<center><button class="btn btn-xs btn-default btn-transparent btn-trans-font">'
                        + item.bucket_type
                        + '</button>'
                        + '</center>'
                    }
                    else {
                        var bucket_type_button = '<center><button class="btn btn-xs btn-success btn-transparent btn-trans-font btn-success-btn">'
                        + item.bucket_type
                        + '</button>'
                        + '</center>'
                    }
                        
                    $('#s3').append(
                        '<tr><td>'
                        + bucket_type_button
                        +'</td><td>'
                        +item.bucket
                        +'</td><td>'
                        + removeCloudAssetButton(item.id) 
                        + '</td></tr>'
                    );
                });
            }
            else {
                $('#s3').append(
                    '<tr><td>'
                    +'</td><td>'
                    + 'No S3 buckets'
                    + '</td><td>'
                    + '</td></tr>'
                );
            }
            if (response.Azure.length !==0) {
                $.each(response.Azure, function (i, item){
                    if (item.bucket_type == "Unmanaged"){
                       var bucket_type_button = '<button class="btn btn-xs btn-default btn-transparent btn-transparent-font">'
                        + item.bucket_type
                        +'</button>'
                    }
                    else {
                        var bucket_type_button = '<button class="btn btn-xs btn-success btn-transparent btn-transparent-font btn-success-btn">'
                        + item.bucket_type
                        +'</button>'
                    }

                    $('#azure').append(
                        '<tr><td>'
                        + bucket_type_button
                        +'</td><td>'
                        +item.bucket
                        +'</td><td>' 
                        + removeCloudAssetButton(item.id) 
                        +'</td></tr>'
                    );
                });
            }
            else {
                $('#azure').append(
                    '<tr><td>'
                    +'</td><td>' 
                    + 'No Azure buckets' 
                    + '</td><td>'
                    + '</td></tr>'
                );
            }
            if (response.GCP.length !==0) {
                $.each(response.GCP, function (i, item){
                    if (item.bucket_type == "Unmanaged"){
                       var bucket_type_button = '<button class="btn btn-xs btn-default btn-transparent btn-transparent-font">'
                        + item.bucket_type
                        +'</button>'
                    }
                    else {
                        var bucket_type_button = '<button class="btn btn-xs btn-success btn-transparent btn-transparent-font btn-success-btn">'
                        + item.bucket_type
                        +'</button>'
                    }

                    $('#gcp').append(
                        '<tr><td>'
                        + bucket_type_button
                        +'</td><td>'
                        +item.bucket
                        +'</td><td>' 
                        + removeCloudAssetButton(item.id) 
                        +'</td></tr>'
                    );
                });
            }
            else {
                $('#gcp').append(
                    '<tr><td>'
                    +'</td><td>'
                    + 'No GCP buckets'
                    + '</td><td>'
                    + '</td></tr>'
                );
            }
            if (response.aws_data.length > 0){
                $.each(response.aws_data, function (i, item){
                    if (item.scan_state == "Completed"){
                        var status = "success"
                    }
                    else if (item.scan_state == "Error"){
                        var status = "failed"
                    }
                    else if (item.scan_state == "Running"){
                        var status = "Loading"
                    }
                    else if (item.scan_state == "NotInitiated"){
                        var status = "Loading"
                    }
                    if (response.aws_data) {
                        $('#aws-asset-table').append(
                            '<tr><td>'
                            + '<center>'
                            +'<button class="btn btn-xs btn-success btn-transparent btn-trans-font btn-success-btn">'
                            + item.token_description
                            +'</button>'
                            +'</center>'
                            +'</td><td>'
                            + item.client_aws_access_token
                            + '</td><td><label id="aws_asset_'
                            + item.id
                            + '">'
                            + status
                            + '</label></td><td>'
                            + item.assets
                            +'</td><td>'
                            + AssetTokenRemoveButton(item.id)
                            + '</td></tr>'
                        );
                    }
                    
                });
            }
            else {
                $('#aws_asset_table').html('');
                $('#aws_asset_table').append(
                    '<tr><td><label style="padding: 5px 5px 5px 5px;">No assets currently loaded</label></td></tr>'
                );
            }
        },
        error:function (xhr, ajaxOptions, thrownError){
            $.growl.error({title:"Oops!", message: thrownError });
        }
    });
}


function addCloudAsset(){
    var cloudregex = /^[0-9a-zA-Z_.-]+$/;
    var category = $('#id_category').val();
    var bucket = $('#id_bucket').val();
    if (bucket && bucket.match(cloudregex)){
       $.ajax({
        url: 'cloud-assets/',
        type: 'POST',
        data: {
            'category': category,
            'bucket': bucket
            },
        success: function(response){
            if(response.status == true){
                createCloudAssetTables();
                $.growl.notice({title:"Success", message: response.message });
            }
            else if(response.status == false){

                $.growl.error({title:response.message, message: response.data.non_field_errors });
            }
            else{
                $.growl.error({title:"Opps!", message: "Some Error occurs!" });
            }
        },
        error:function (xhr, ajaxOptions, thrownError){
            $.growl.error({title:"Oops!", message: thrownError });
        }
        });
    }
    else if(bucket && bucket.match(cloudregex)!=true){
        $.growl.error({title:"Alert", message: "CloudAsset names may only contain letters, numbers, and spaces" });

    }
    else{
        $.growl.error({title:"Alert", message: "Please Enter data in the bucket" });
    }
}


function UpdateHostsCount(){
    $.ajax({
        type: "GET",
        async: false,
        url: 'update-count/',
        success: function(response)
        {
            $('#host_text').text('Hosts (' + response.total_host + ')');
            $('#application_text').text('Applications (' + response.total_applications + ')');
            $('#domain_text').text('Domains (' + response.total_domains + ')');
            $('#cloud-assets').text('Cloud Assets (' + response.total_assets + ')');
            $('#excluded_link').text('Excluded (' + response.total_exclude + ')');
            $('#network_text').text('Networks (' + response.total_network + ')');
        },
        error:function (xhr, ajaxOptions, thrownError){
            $.growl.error({title:"Oops!", message: thrownError });
        }
    });
}


function RemoveHost(obj){
    host_id = $(obj).attr("id");
    $.ajax({
        url: 'delete/',
        type: 'GET',
        data: {
            'host_id[]': host_id
        },    
        success: function(response){
            alertify.confirm((response.ips_count+","+response.vul_count), function (e) {
            if(e){
                $.ajax({
                url: 'delete/',
                type: 'DELETE',
                data: {
                    'host_id[]': host_id
                },
                success: function(response){
                    if (response.status == true){
                        UpdateHostsCount();
                        clicked_tr = $(obj).parent().parent();
                        clicked_tr.remove();
                        $.growl.notice({title:"Success", message: "Host Deleted successfully!" });
                        createHostTable();
                        whoisMap();
                    }
                    else{
                        $.growl.error({title:"Error!", message: "Unable to delete the Host" });
                    }
                }
            });
            } 
            else {
                
            }
            });
        }
    });
    
}


function DownloadFile(elem){
    report_id = $(elem).val();
    $.ajax({
        url: '/reports/' + report_id + '/',
        type: 'GET',
        success: function(response){
            if (response==false){
                $.growl.error({title:"Error!", message: "Unable to Download File" });
            }
            else{
                var message_response = response.message
                var file_link = response.link
                var aTag = document.createElement('a');
                aTag.setAttribute('href',file_link);
                document.body.appendChild(aTag);
                aTag.click();$.growl.notice({title:"Success", message: "File Downloaded Successfully!" });
            }
        }
    });
}


function DeleteReportFile(elem){
    report_id = $(elem).val();
    alertify.confirm("delete report", function (e) {
        if (e){
            $.ajax({
                url: '/reports/' + report_id + '/',
                type: 'DELETE',
                dataType: 'json',
                success: function(data){
                    if (data == true){
                        clicked_tr = $(elem).parent().parent();
                        clicked_tr.remove();
                        $.growl.notice({title:"Success", message: "Report Deleted successfully!" });
                    }
                    else{
                        $.growl.error({title:"Error!", message: "Unable to delete the Report" });
                    }
                }
            });
        }
    });
}


function awsKeyStatus(id)
{
    $.ajax({
        url : '/api/aws-key-status/' + id,
        type : 'GET',
        success: function(response){
            if (response.status == true && response.aws_status){
                if (response.aws_status == "Error"){
                    $("#aws_asset_"+id).text('failed');
                }
                else{
                    $("#aws_asset_"+id).text(response.aws_status);
                }
                if (response.aws_status == "success"){
                    UpdateHostsCount();
                    createNetworkTable();
                    createCloudAssetTables();
                    // stop_aws_get_status_time_interval();
                }
            }
        }
    });
}


function awscheckStatus()
{
    var Label_id = null;
    $('#aws_asset_table tr').each(function(i) {
        var label_id = $(this).find("label").attr('id');
        token_status = $('#'+label_id).text();
        if (token_status == "Loading"){
            Label_id = label_id
        }
    });
    if (Label_id !== null){
        var label_val = $('#'+Label_id).text();
        if (label_val){
            aws_asset_id = Label_id.replace("aws_asset_", '');
            if (label_val == "Loading"){
                awsKeyStatus(aws_asset_id);
            }
        }
    }
    else{
        stop_aws_get_status_time_interval();
    }
}

var aws_set_interval_obj;

function set_aws_get_status_time_interval()
{
    aws_set_interval_obj = setInterval(awscheckStatus, 5000);
}


function stop_aws_get_status_time_interval()
{
    console.log('token_processing_finished');
    clearInterval(aws_set_interval_obj);
}


function addToken(){
    var aws_access_token_id = $("#aws_access_token_id").val();
    var aws_access_token_description = $("#aws_access_token_description_id").val();
    var aws_secret_token_id = $("#aws_secret_token_id").val();
    var form_valid = $("#aws_configuration").valid();
    $("#aws_access_token_id").val('');
    $("#aws_secret_token_id").val('');
    $("#aws_access_token_description_id").val('');
    $('#aws_asset_button').prop('disabled',true);
    if (form_valid){
        $.ajax({
            url : 'aws-assets/',
            type : 'POST',
            data: {
                    'aws_access_token_id': aws_access_token_id,
                    'aws_secret_token_id': aws_secret_token_id,
                    'aws_access_token_description': aws_access_token_description
                },
            success: function(response){
                if (response.status == true){
                    $.growl.notice(
                        {
                            title:"Success",
                            message: response.message
                        }
                    );
                    var aws_asset_tr = '<tr><td><center><button class="btn btn-xs btn-success btn-transparent btn-trans-font btn-success-btn">'
                        + response.data.token_description
                        + '</button></center></td><td>'
                        + response.data.client_aws_access_token
                        + '</td><td><label id="aws_asset_'
                        + response.data.id
                        + '">Loading</label></td><td></td><td>'
                        + AssetTokenRemoveButton(response.data.id)
                        + '</td></tr>';
                    var aws_table_len = $('#aws-asset-table').length;
                    if (aws_table_len == 0){
                        $('#aws_asset_table').html('');
                        var aws_asset_thead = '<thead><tr><th class="aws_assets_heading">'
                            + 'Description'
                            + '</th><th class="aws_assets_heading">'
                            + 'Access Token'
                            + '</th><th class="aws_assets_heading">'
                            + 'Status'
                            + '</th><th class="aws_assets_heading">'
                            + 'Assets'
                            + '</th><th class="aws_assets_heading">'
                            + 'Remove'
                            + '</th></tr></thead>';
                        var aws_asset_tbody = '<tbody id="aws-asset-table">'
                            + aws_asset_tr
                            + '</tbody>';
                        var aws_asset_tdata = aws_asset_thead + aws_asset_tbody;
                        $('#aws_asset_table').append(aws_asset_tdata);
                    }
                    else {
                        $('#aws-asset-table').append(aws_asset_tr);
                    }
                    $('#aws_asset_button').prop('disabled',false);
                    set_aws_get_status_time_interval();
                }
                else if (response.status == false){
                    if (response.status_code == 400){
                        $('#aws_asset_button').prop('disabled',false);
                        $.growl.error(
                            {
                                title: response.message,
                                message: response.errors['client_aws_access_token']
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
                    $.growl.error({title:"Error!", message: "Unable to add token" });
               }
            }
        });
    }
}


function resetButton(){
    $('#load').text("Add Hosts")
    $('#load').prop('disabled',true);
    $('#ipaddress').keyup(function(){
        $('#load').prop('disabled', this.value == "" ? true : false);
    })
    $('#load').click(function () {
        var btn = $(this)
        btn.button('Adding...')
    })
} 

$(document).ready(function () {
    var frm = $('#ipsform');
    frm.submit(function () {
        $.ajax({
            type: frm.attr('method'),
            url: 'host/',
            data: frm.serialize(),
            success: function (response) {
                if (response.status == true){
                    UpdateHostsCount();
                    $.growl.notice({
                        title:"Success",
                        message: response.message
                    });
                    createHostTable();
                    whoisMap();
                    $('#load').prop('disabled',false);
                    $('#ipaddress').val('');
                    resetButton();
                }
                else if (response.status == false) {
                    if (response.status_code == 400){
                        $.growl.error({
                            title: response.message,
                            message: response.errors
                        });
                    }
                    else {
                        $.growl.error({
                            title: "Oops!",
                            message: response.message
                        });
                    }
                    $('#load').prop('disabled',false);
                    $('#ipaddress').val('');
                    resetButton();
               }
            },
            error:function (xhr, ajaxOptions, thrownError){
                $('#load').prop('disabled',false);
                $('#ipaddress').val('');
                resetButton();
                $.growl.error({title:"Oops!", message: thrownError });
            }
        });
        return false;
    });
    createNetworkTable()

    $('#aws_configuration').validate({ // initialize the plugin
        // rules: {
        //     aws_access_token_id: {
        //         required: true
        //     },
        //     aws_secret_token_id: {
        //         required: true
        //     }
        // },
        rules: {
            aws_access_token_id: {
                required: true,
            }
        },
    });

    // Check or Uncheck All checkboxes in host.html
    $("#checkall").change(function(){
        var checked = $(this).is(':checked');
        if(checked){
            $(".checkbox").each(function(){
                $(this).prop("checked",true);
            });
        }
        else{
            $(".checkbox").each(function(){
                $(this).prop("checked",false);
            });
        }
    });

    // Changing state of CheckAll checkbox
    $(".checkbox").click(function(){
        if($(".checkbox").length == $(".checkbox:checked").length) {
            $("#checkall").prop("checked", true);
        }
        else {
            $("#checkall").removeAttr("checked");
        }

    });

    // To create cloud asset table and to update status of aws token added
    createCloudAssetTables();
    set_aws_get_status_time_interval();
});


function delete_action(){
    var host_id = [];
    $(':checkbox:checked').each(function(i){
        host_id[i] = $(this).val();
    });
    //tell you if the array is empty
    if(host_id.length === 0) {
        $.growl.warning({message: "Please Select atleast one host"});
    }
    else {
        $.ajax({
            url: 'delete/',
            type: 'GET',
            data: {
                'host_id[]': host_id
            },
            success: function(response){
                if (response.status == true){
                    alertify.confirm((response.ips_count+","+response.vul_count), function (e) {
                        if(e){
                            $.ajax({
                                url: 'delete/',
                                type: 'DELETE',
                                data: {
                                    'host_id[]': host_id
                                },
                                dataType: 'json',
                                success: function(response){
                                    if (response.status == true){
                                        UpdateHostsCount();
                                        $("#checkall").prop("checked", false);
                                        $.growl.notice({
                                            title:"Success",
                                            message: response.message
                                        });
                                        createHostTable();
                                        whoisMap();
                                    }
                                    else{
                                        $.growl.error({
                                            title:"Opps !",
                                            message: response.message
                                        });
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
}

//remove multiple host from host
function checked_action(){
    var value = $('#selected_host_value').val();
    if(value == "selected"){
        $.growl.warning({message: "No action selected"});
    }
    if (value == "delete"){
        delete_action();
    }
}

function createDomainTable(){
    $.ajax({
        type: "GET",
        async: false,
        url: 'domains/',
        success: function(response) {
            UpdateHostsCount();
            if ((response.domains).length > 0){
                $('.domain_table_parent').show();
                $('#domain-table').html('');
                $.each(response.domains, function (i, item){
                    var counter = parseInt(i);
                    var count = counter+1;
                    var counter_td = '<td>' + count + '</td>'
                    var domain_name_td = '<td>' + item.domain_name + '</td>'
                    var network_type_td = '<td>' + '<center>' + item.network_type + '</center>' + '</td>'
                    var domain_dlt_btn =  '<a onclick="delete_domain(' + item.id + ');"><span class="icon-bin"></span></a>'
                    var action_td = '<td>' + domain_dlt_btn  + '</td>';
                    var full_tr = '<tr id="domain_tr_' + item.id + '">' + counter_td + domain_name_td + network_type_td + action_td + '</tr>'
                    $('#domain-table').append(full_tr)
                })
            }
            else{
                $('.domain_table_parent').hide();
            }
            if ((response.domains).length > 0){
                $('.sub-domain-table').html('');
                $.each(response.domains, function (i, item){
                    if ((item.sub_domains).length > 0){
                        var div_panel_start = "<div class='panel'>"
                        var div_panel_end = "</div>"
                        var div_panel_body_start = "<div class='panel-body'  style='display: table;'>";
                        var div_panel_body_end = "</div>";
                        var div_table_responsive_start = "<div class='table-responsive' style='overflow-x: hidden;'>";
                        var div_table_responsive_end = "</div>";
                        var sub_domain_table_start = "<table id='subdomain-data-table-" + item.index + "' class='subdomain-data-table-" + item.index + " table table-bordered table-hover table-condensed no-margin'><thead><tr><th class='notifications_heading'>Domain</th><th class='notifications_heading'>IP</th><th class='notifications_heading'>Scope</th><th class='notifications_heading'>Discovered</th></tr></thead><tbody>";
                        var sub_domain_table_end = "</tbody></table>";
                        var table_id = "#subdomain-tbody-" + item.index;
                        var sub_domain_tr = []
                        $.each(item.sub_domains, function (i, item){
                            if (item.in_scope){
                                var scope_button = "<button class='btn btn-success btn-transparent btn-xs cloud_padding_pass'>In scope</button>"
                            }
                            else{
                                var scope_button = "<button class='btn btn-danger btn-transparent btn-xs cloud_padding_fail'>Out of scope</button>"
                            }
                            var sub_domain_trs = 
                                "<tr id='subdomain_" + item.id + "'><td>" + item.subdomain
                                + "</td><td> " + item.domain_host + "</td><td><center>"
                                + scope_button + "</center></td><td>" + item.created
                                + "</td></tr>";
                            sub_domain_tr.push(sub_domain_trs)
                        })
                        var sub_domain_table_tr = sub_domain_tr.join().replace(/,/g, '');
                
                        if (i+1 == response.first_subdomain_index){
                            var sub_domain_heading = "<div class='panel-heading'><h3>Sub Domains</h3></div>";
                            var hidden_input = "<input type='hidden' id='sub_domain_length' value='" + response.sub_domain_length + "'>";
                            var full_tr =
                                hidden_input + div_panel_start + sub_domain_heading + div_panel_body_start
                                + div_table_responsive_start + sub_domain_table_start
                                + sub_domain_table_tr + sub_domain_table_end
                                + div_table_responsive_end + div_panel_body_end + div_panel_end;
                        }
                        else{
                            var full_tr =
                                div_panel_start + div_panel_body_start
                                + div_table_responsive_start + sub_domain_table_start
                                + sub_domain_table_tr + sub_domain_table_end
                                + div_table_responsive_end + div_panel_body_end + div_panel_end;
                        }
                        $('.sub-domain-table').append(full_tr);
                        
                    }
                })
                var sub_domain_length = $('#sub_domain_length').val();
                var length = parseInt(sub_domain_length, 10);
                for (var i = 0; i < length; i++) {
                    var subdomain_id = ".subdomain-data-table-" + (i+1);
                    $(subdomain_id).DataTable( {
                        "paging": false,
                        "bInfo" : false
                    } );
                    $.fn.dataTable.ext.errMode = 'none'; 
                    $(subdomain_id).on( 'error.dt', function ( e, settings, techNote, message ) {
                        // console.log( 'An error has been reported by DataTables: ', message );
                    } ).DataTable();
                } 
                $('.dataTables_filter').css('display','none');
                $('.dataTables_info').css('display','none');
            }
        },
        error:function (xhr, ajaxOptions, thrownError){
            $.growl.error({title:"Oops!", message: thrownError });
        }
    });
}


function createApplicationTable(){
    $.ajax({
        type: "GET",
        async: false,
        url: 'applications/',
        success: function(response) {
            UpdateHostsCount();
            if (response.length >= 0){
                $('#application-table').html('');
                $.each(response, function(i, item){
                    var counter = parseInt(i);
                    var count = counter+1;
                    var counter_td = '<td>' + count + '</td>'
                    var application_url_td = '<td>' + item.application_url + '</td>';
                    var network_type_td = '<td>' + '<center>' +  item.network_type  + '</center>' + '</td>'
                    var full_tr = '<tr id="application_tr_' + item.id + '">' + counter_td + application_url_td + network_type_td + "<td> <center><button value='"  + item.id + "' class='host-button' onclick='removeApplicationData(this)''><span class='icon-bin'></span></button></center></tr>"
                    $('#application-table').append(full_tr)
                })
            }
        },
        error: function (xhr, ajaxOptions, thrownError){
            $.growl.error({title:"Oops!", message: thrownError });
        }
    });
}


function delete_domain(domain_id){
    $.ajax({
        url: 'domains/' + domain_id + "/",
        type: "DELETE",
        dataType: 'json',
        success: function(response){
            if (response.status == true){

                $.growl.notice({title:"Success", message: response.message });
                createDomainTable();
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
        
        
function addApplicationUrl(){
    var application_url = $('#application_url_input_id').val();
    var network_type = $('#application_network_type').val();
    if (application_url) {
        if (network_type) {
            $.ajax({
                url: 'applications/',
                type: 'POST',
                data: {
                    'application_url': application_url,
                    'network_type': network_type
                    },
                success: function(response) {
                    if (response.status == true){
                        UpdateHostsCount();
                        $.growl.notice({
                            title: "Success",
                            message: "Application added successfully!"
                        });
                        $('#application_url_input_id').val("");
                    }
                    else if (response.status == false) {
                        if (response.status_code == 400){
                            if (response.errors.application_url){
                                var error = response.errors.application_url;
                            }
                            else{
                                var error = response.errors;
                            }
                            $.growl.error({
                                title: response.message,
                                message: error
                            });
                        }
                        else {
                            $.growl.error({
                                title: "Error",
                                message: response.message
                            });
                        }
                    }
                    createApplicationTable();
                }
                });
            }
        else {
            $.growl.warning({message: "Please Select Network Type" });
        }
    }    
    else{
        $.growl.warning({title:"Alert", message: "Please Enter Application Name" });
    }
}

function removeApplicationData(elem){
    alertify.confirm("application", function (e) {
    if (e){
        application_id = $(elem).val();
        $.ajax({
            url: '/hosts/applications/' + application_id + '/',
            type: 'DELETE',
            success: function(data){
                if (data.status == true){
                    $.growl.notice(
                        {
                            title:"Success",
                            message: data.message
                        }
                    );

                }
                else{
                    $.growl.error(
                        {
                            title:"Error!",
                            message: data.message
                        }
                    );
                }
                createApplicationTable();
            }
        });
    }
    });    
}
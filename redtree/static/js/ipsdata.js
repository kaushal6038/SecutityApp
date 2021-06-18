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

var myVar;
$(document).ready(function(){
  $('.tooltips').removeClass("hidden");
  $('.tooltips').hide();

});

function showClipboard(id) {
    clearTimeout(myVar);
    // $('.tooltips').hide();
    $('.tooltips').fadeOut(500);
    tooltip_id = "#tool-tip-" + id;
    //$(tooltip_id).show();
    $(tooltip_id).stop(true).hide().fadeIn(2000);
}

function hideLabelClipboard(id){
    $('.tooltips').fadeOut();
    $('.tooltips').fadeOut(300);
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

$.ajaxPrefilter(function(options, originalOptions, jqXHR){
    if (options['type'].toLowerCase() === "post") {
        jqXHR.setRequestHeader('X-CSRFToken', getCookie('csrftoken'));
    }
});
var ipstable = $('#iptrackinfo')[0];
function IpTrackInfo(obj)
    {
        var left = $("#external_host_table").width();
        var offset = $(obj).position();
        $('#iptrackinfo').html('');
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
                $('.external_data_right').css("padding-top", (top) +'px');
                $('.external_data_right').css("margin-left", (left) +'px');
                $('.external_data_right').css("width",'100px;');
            }
            else {
            $('.external_data_right').css("width",'125px');
            $.each(data, function (i, item){
                $('.external_data_right').css("padding-top", (top) +'px');
                $('.external_data_right').css("margin-left", (left + 5) +'px');
                $('#iptrackinfo').append('<tr id="' + data[i].id + '" ><td>' + data[i].ip + '</td></tr>');
            });
            }
            $( button ).on( 'click', function ( e ) {
            $( ipstable ).show();
            e.stopPropagation();
            });
           }
       });
    }

$(document).on("click",function(e) {
   if ($(e.target).is("#hosts *, #external_host_table *")){
    $("#iptrackinfo").show();
   }
   else{
     $("#iptrackinfo").html('');
   }
});

$( document ).on( 'keydown', function ( e ) {
    if ( e.keyCode === 27 ) {
        $("#iptrackinfo").html('');
    }
});

$(document).click(function(e) {

  if( e.target.id != 'iptrackinfo') {
    $("#iptrackinfo *").hide();
  }
});

$(document).click(function(e) {

  if( e.target.id != 'in_iptrackinfo') {
    $("#in_iptrackinfo *").hide();
  }
});



var in_ipstable = $('#in_iptrackinfo')[0];
function in_IpTrackInfo(obj)
    {
        var left = $("#internal_host_table").width();
        var offset = $(obj).position();
        $('#in_iptrackinfo').html('');
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
                $('.internal_data_right').css("padding-top", (top) +'px');
                $('.internal_data_right').css("margin-left", (left) +'px');
                $('.internal_data_right').css("width",'100px;');
            }
            else {
            $('.internal_data_right').css("width",'125px');
            $.each(data, function (i, item){
                $('.internal_data_right').css("padding-top", (top) +'px');
                $('.internal_data_right').css("margin-left", (left + 5) +'px');
                $('#in_iptrackinfo').append('<tr id="' + data[i].id + '" ><td>' + data[i].ip + '</td></tr>');
            });
            }
            $( button ).on( 'click', function ( e ) {
            $( in_ipstable ).show();
            e.stopPropagation();
            });
           }
       });
    }

$(document).on("click",function(e) {
   if ($(e.target).is("#hosts *, #internal_host_table *")){
    $("#in_iptrackinfo").show();
   }
   else{
     $("#in_iptrackinfo").html('');
   }
});

$( document ).on( 'keydown', function ( e ) {
    if ( e.keyCode === 27 ) {
        $("#in_iptrackinfo").html('');
    }
});

function CloseVul(obj){
    alertify.confirm("Are you sure, you want to Close this Vulnerability?", function (e) {
    if(e){
        $.ajax({
        url: '/retest/close',
        type: 'POST',
        data: {
            'vul_id': $(obj).attr("id")
            },
        dataType: 'json',
        success: function(data){
            if (data == 'done'){
                clicked_ul = $(obj).parent().parent();
                clicked_li = $(obj).parent();
                clicked_li.remove();
                clicked_ul.append('<li><button class="btn btn-warning" style="pointer-events:none;">Closed</button></li>');
                $.growl.notice({title:"Success", message: "Vulnerability closed successfully!"});
            }
            else{
                $.growl.error({title:"Error!", message: "Unable to close the Vulnerability"});
            }
            }
        });
    } 
    else {
        
    }
    });
}


function deleteVulnerability(obj){
    alertify.confirm("Are you sure, you want to delete this Vulnerability?", function (e) {
    if(e){
        var virtue_id  = $(obj).val();
        var post_url = '/vulnerability/delete/' + virtue_id + '/'
        $.ajax({
            url: post_url,
            type: 'get',
            dataType: 'json',
            success: function(data){
                if (data.status == true){
                    $.growl.notice({title:"Success", message: "Vulnerability Deleted successfully!"});
                    setTimeout(function() {
                      window.location.href = "/vulnerabilities/";
                    }, 2000);
                }
                else{
                    $.growl.error({title:"Error!", message: data});
                }
            }
        });
    }
    else {

    }
    });
}

function delete_domain(domain_id){
    $.ajax({
        url: '/domains/' + domain_id + "/",
        type: "POST",
        dataType: 'json',
        success: function(response){
            if (response.status == true){

                $.growl.notice({title:"Success", message: response.message });

                $('.remove').each(function(i){
                $("#domain_"+ domain_id).remove();
                });
                
            }
            else {
                $.growl.error({title:"Oops!", message: response.message });
           }
        },
        error:function (xhr, ajaxOptions, thrownError){
            alert(thrownError);
        }
    });
}

function delete_subdomain(domain_id){
    $.ajax({
        url: '/subdomains/' + domain_id + "/",
        type: "POST",
        dataType: 'json',
        success: function(response){
            if (response.status == true){

                $.growl.notice({title:"Success", message: response.message });

                $('.remove').each(function(i){
                $("#subdomain_"+ domain_id).remove();
                });
                
            }
            else {
                $.growl.error({title:"Oops!", message: response.message });
           }
        },
        error:function (xhr, ajaxOptions, thrownError){
            alert(thrownError);
        }
    });
}

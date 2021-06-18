var $border_color = "#F5F8FA";
var $grid_color = "#e1e8ed";
var $default_black = "#666";
var $red = "#E24B46";
var $grey = "#999999";
var $yellow = "#FAD150";
var $pink = "#666";
var $blue = "#d12a16";
var $green = "#6EBB41";


/* Vertical Responsive Menu */
'use strict';
var tid = setInterval( function () {
    if ( document.readyState !== 'complete' ) return;
    clearInterval( tid );
    var querySelector = document.querySelector.bind(document);
    var nav = document.querySelector('.vertical-nav');

//  // Minify menu on menu_minifier click
//  querySelector('.collapse-menu').onclick = function () {
//      nav.classList.toggle('vertical-nav-sm');
//      $('.dashboard-wrapper').toggleClass(('dashboard-wrapper-lg'), 200);
//      $("i", this).toggleClass("icon-menu2 icon-cross2");
//  };

    // Toggle menu click
    querySelector('.toggle-menu').onclick = function () {
        nav.classList.toggle('vertical-nav-opened');
    };

}, 1000 );


// Sidebar Dropdown Menu
$(function () {
    $('.vertical-nav').metisMenu();
});

;(function ($, window, document, undefined) {

    var pluginName = "metisMenu",
    defaults = {
        toggle: true
    };

    function Plugin(element, options) {
        this.element = element;
        this.settings = $.extend({}, defaults, options);
        this._defaults = defaults;
        this._name = pluginName;
        this.init();
    }

    Plugin.prototype = {
        init: function () {
            var $this = $(this.element),
            $toggle = this.settings.toggle;

            $this.find('li.active').has('ul').children('ul').addClass('collapse in');
            $this.find('li').not('.active').has('ul').children('ul').addClass('collapse');

            $this.find('li').has('ul').children('a').on('click', function (e) {
                e.preventDefault();

                $(this).parent('li').toggleClass('active').children('ul').collapse('toggle');

                if ($toggle) {
                    $(this).parent('li').siblings().removeClass('active').children('ul.in').collapse('hide');
                }
            });
        }
    };

    $.fn[ pluginName ] = function (options) {
        return this.each(function () {
            if (!$.data(this, "plugin_" + pluginName)) {
                $.data(this, "plugin_" + pluginName, new Plugin(this, options));
            }
        });
    };

})(jQuery, window, document);


// scrollUp full options
$(function () {
    $.scrollUp({
        scrollName: 'scrollUp', // Element ID
        scrollDistance: 180, // Distance from top/bottom before showing element (px)
        scrollFrom: 'top', // 'top' or 'bottom'
        scrollSpeed: 300, // Speed back to top (ms)
        easingType: 'linear', // Scroll to top easing (see http://easings.net/)
        animation: 'fade', // Fade, slide, none
        animationSpeed: 200, // Animation in speed (ms)
        scrollTrigger: false, // Set a custom triggering element. Can be an HTML string or jQuery object
        //scrollTarget: false, // Set a custom target element for scrolling to the top
        scrollText: '<i class="icon-chevron-up"></i>', // Text for element, can contain HTML // Text for element, can contain HTML
        scrollTitle: false, // Set a custom <a> title if required.
        scrollImg: false, // Set true to use image
        activeOverlay: false, // Set CSS color to display scrollUp active point, e.g '#00FFFF'
        zIndex: 2147483647 // Z-Index for the overlay
    });
});

// Material Button
var element, circle, d, x, y;
$(".btn").click(function(e) {
    element = $(this);
    if(element.find(".circless").length == 0)
    element.prepend("<span class='circless'></span>");
    circle = element.find(".circless");
    circle.removeClass("animate");
    if(!circle.height() && !circle.width())
    {
        d = Math.max(element.outerWidth(), element.outerHeight());
        circle.css({height: d, width: d});
    }
    x = e.pageX - element.offset().left - circle.width()/2;
    y = e.pageY - element.offset().top - circle.height()/2;

    circle.css({top: y+'px', left: x+'px'}).addClass("animate");
});

// Loading
$(function() {
    $(".loading-wrapper").fadeOut(2000);
});

//alert

$(document).ready(function(){
    setTimeout(function(){
        $('#error-alert').fadeOut();}, 6000);
});


// Bootstrap Dropdown Hover
$(function(){
    $("#header-actions .dropdown").hover(
        function() {
            $('.dropdown-menu', this).stop( true, true ).fadeIn("fast");
            $(this).toggleClass('open');
        },
        function() {
            $('.dropdown-menu', this).stop( true, true ).fadeOut("fast");
            $(this).toggleClass('open');
        }
    );
});


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


var host_array=[];
var plugindata = $("#host_array").val();
if (plugindata != ""){
    host_array.push(plugindata);
}
$(document).ready(function(){
    $('#save').prop('disabled',true);
    $('#host').keyup(function(){
        $('#save').prop('disabled', this.value == "" ? true : false);
    })
});
function hostData(){
    var host = $("#host").val();
    host_array.push(host);
    $("#host_array").val(host_array);
    $("#host").val("");
    $('#save').prop('disabled',true);
}

$(function(){
    $("#header-actions .dropdown").hover(            
        function() {
            $('.dropdown-menu', this).stop( true, true ).fadeIn("fast");
            $(this).toggleClass('open');
        },
        function() {
            $('.dropdown-menu', this).stop( true, true ).fadeOut("fast");
            $(this).toggleClass('open');
        }
    );
});

$(document).ready(function() {
    function GetNotifications(){
        $.ajax({
            type: "GET",
            url: "/notifications",

        success: function(response) {
            if (response.retest > 0 && response.app_notifications.length > 0){
                $('#notification-ul').html('');
                $('#notification-icon').addClass('info-label blue-bg');
                $('#notification-icon').text(response.retest + response.app_notifications.length);
                var notification_text= response.retest + " new retest requests have been made."
                link = "<a href='/retest' style='font-size:14px;'>" + notification_text + "</a>"
                html_content = "<li><div class='details' id='notification-div'>"+ link + "</div></li>"
                $('#notification-ul').append(html_content);
                $('#notification-ul').removeClass('hidden');
                $('#notifications-status').text("You have " + response.retest + " new notifications");
                $.each(response.app_notifications, function (i, item){
                    var notification_text=(item.message).replace(/<(.|\n)*?>/g, '');
                    var notification_time_ago = item.created_at;
                    link = "<a href='/redtree-error-log' style='font-size:14px; color:red; white-space:pre-wrap;'>" + notification_text + "</a>"
                    html_content = "<li><div class='col-lg-12 col-md-12'>\
                            <div class='col-lg-2 col-md-2 notication-time'>" + notification_time_ago + "</div>\
                            <div class='col-lg-10 col-md-10 notification-data'>" + link +"</div></li>\
                        </div>\
                    </li>"
                    $('#notification-ul').append(html_content);
                    $('#notification-ul').removeClass('hidden');
                    
                });
            }
            else if (response.retest == 0 && response.app_notifications.length > 0){
                $('#notification-ul').html('');
                $.each(response.app_notifications, function (i, item){
                    $('#notification-icon').addClass('info-label blue-bg');
                    $('#notification-icon').text(response.app_notifications.length);
                    var notification_text=(item.message).replace(/<(.|\n)*?>/g, '');
                    var notification_time_ago = item.created_at;
                    link = "<a href='/redtree-error-log' style='font-size:14px; color:red; white-space:pre-wrap;'>" + notification_text + "</a>"
                    html_content = "<li><div class='col-lg-12 col-md-12'>\
                            <div class='col-lg-2 col-md-2 notication-time'>" + notification_time_ago + "</div>\
                            <div class='col-lg-10 col-md-10 notification-data'>" + link +"</div></li>\
                        </div>\
                    </li>"

                    $('#notification-ul').append(html_content);
                    $('#notification-ul').removeClass('hidden');
                });
            }
            else if (response.retest > 0 && response.app_notifications.length == 0){
                $('#notification-ul').html('');
                $('#notification-icon').addClass('info-label blue-bg');
                $('#notification-icon').text(response.retest);
                var notification_text= response.retest + " new retest requests have been made."
                link = "<a href='/retest' style='font-size:14px;'>" + notification_text + "</a>"
                html_content = "<li><div class='details' id='notification-div'>"+ link + "</div></li>"
                $('#notification-ul').append(html_content);
                $('#notification-ul').removeClass('hidden');
                $('#notifications-status').text("You have " + response.retest + " new notifications");
            }
            
        }
        });
    }
    GetNotifications();

    function Scanningstatus(){
        $.ajax({
            type: "GET",
            url: "/scanningstatus",

        success: function(response) {
            if (response == 1){
                $('#scanning-text').text('scanning is active');
                $('#scanning-bar').removeClass('inactive-scanning');
                $('#scanning-bar').removeClass('unable-scanning');
                $('#scanning-bar').addClass('active-scanning');
            }
            else if(response == 0) {
                $('#scanning-text').text('scanning is inactive');
                $('#scanning-bar').removeClass('active-scanning');
                $('#scanning-bar').removeClass('unable-scanning');
                $('#scanning-bar').addClass('inactive-scanning');
            }
            else {
                $('#scanning-text').text('unable to fetch scanning status');
                $('#scanning-bar').removeClass('active-scanning');
                $('#scanning-bar').removeClass('inactive-scanning');
                $('#scanning-bar').addClass('unable-scanning');
            }
        }
        });
    }
    Scanningstatus();

    // $('#update-notification').on("click", function(){
    //     $.ajax({
    //         type: "GET",
    //         url: "/update-notifications",

    //     success: function(response) {
    //         console.log()
    //         if (response > 0){
    //             $('#notification-icon').addClass('info-label blue-bg');
    //             $('#notification-icon').text(response);
    //             $('#notifications-count').text(response + " new retest requests have been made.");
    //             $('#notifications-status').text("You have " + response + " new notifications");
    //             $('#notification-ul').removeClass('hidden');
    //         }
    //     }
    //     });
    // });
    function PushNotifications(){
        setInterval(GetNotifications, 15000);
    }
    function HoldNotify(){
        setTimeout(PushNotifications, 15000);
    }
    HoldNotify();
});

$('.edit-btn').each(function() {
 $(this).on('click', function() {
    $(this).parent().parent().find('.clickable-configuration').addClass('hidden');
    $(this).parent().parent().find('.clickable-configuration-data').removeClass('hidden');
 })
})
$('.cancel').on('click',function(){
    $(this).parent().parent().parent().find('.clickable-configuration-data').addClass('hidden');
    $(this).parent().parent().parent().find('.clickable-configuration').removeClass('hidden');
})

$(document).ready(function() {
    var sub_domain_length = $('#sub_domain_length').val();
    var length = parseInt(sub_domain_length, 10);
    for (var i = 0; i < length; i++) {
        var subdomain_id = ".subdomain-data-table-" + (i+1);
        $(subdomain_id).DataTable( {
            "paging": false,
        
        } );
        $.fn.dataTable.ext.errMode = 'none'; 
        $(subdomain_id).on( 'error.dt', function ( e, settings, techNote, message ) {
            // console.log( 'An error has been reported by DataTables: ', message );
        } ).DataTable();
    }
    
} );

$(document).ready(function() {
    $('#nessus-datatable').DataTable( {
        "paging": false,
        dom: 'Bfrtip',
        buttons: [
            'copy', 'csv', 'excel', 'pdf', 'print'
        ]
    } );
} );

function adduser(data){
    var name = $('#new_user_name').val();
    var email = $('#new_user_email').val();
    if (name && email) {
        $.ajax({
                type: "POST",
                url: "/add-user",
                data: {
                    'name': name,
                    'email': email
                },
                dataType: 'json',
            success: function(response) {
                if (response.status){
                    $.growl.notice({title:"Success", message: response.message});
                    setTimeout(function() {
                        window.location.href = "/settings/";
                    }, 1000);
                }   
                else{
                    $.growl.error({title:"Error", message: response.message});
                } 
            },
        });
    }
    else{
        $.growl.error({title:"No Data Provided", message: "Please enter data!"});
    }
}

function edit_user(id){
    var name_id = '#edit-user-name-'+id;
    var email_id = '#edit-user-email-'+id;
    var name = $(name_id).val();
    var email = $(email_id).val();
    if (name && email) {
        $.ajax({
                type: "POST",
                url: "/edit-user",
                data: {
                    'user_id' : id,
                    'name': name,
                    'email': email
                },
                dataType: 'json',
            success: function(response) {
                if (response.status == true){
                    $.growl.notice({title:"Success", message: response.message});
                    setTimeout(function() {
                        window.location.href = "/settings/";
                    }, 1000);
                }   
                else{
                    if (response.message.email){
                        $.growl.error({title:"Error", message: response.message.email});
                    }
                    else{
                        $.growl.error({title:"Error", message: response.message});
                    }
                } 
            },
        });
    }
    else{
        $.growl.notice({title:"No Data Provided", message: "Username and Email are required!"});
    }
}


function kbmapdata(obj){
    $("#nessus-title ").attr("value", '');
    $("#nessus-search").attr("placeholder", '');
    $("#modal-pluginid").attr("value", "");
    plugin_id = $(obj).data('plugin_id')
    var name = $(obj).data('name')
    console.log(plugin_id, name)
    var text = "Search";
    $("#nessus-title ").attr("value", name);
    $("#nessus-search").attr("placeholder", text);
    $("#modal-pluginid").attr("value", plugin_id);
    $('#modal-table').html('');
    $("#nessus-search").val('');
}

$(document).ready( function(){
    $('#nessus-search').keyup(function(){
        var title = $(this).val();
        if (title.length >= 3) {
            $.ajax({
            type: "POST",
            url: '/nessus/search-title/',
            data: {
              'title': title
            },
            dataType: 'json',
            success: function (response) {
              if (response.article.length > 0){
                    $('#modal-table').html('');
                    $.each(response.article, function(i, item){
                        var counter = parseInt(i);
                        var article_type = '<td>' + item.article_type + '</td>';
                        var article_title = '<td>' + '<center>' +  item.title  + '</center>' + '</td>'
                        var full_tr = '<tr id="application_tr_' + item.id + '">' +  article_type + article_title + "<td> <center><button value='"  + item.id + "' class='btn btn-default btn-transparent btn-transparent-font plugin_id_value' onclick='addMapData(this)'>Map</button></center></tr>"
                        $('#modal-table').append(full_tr)
                    })
                }
            },
            error: function (xhr, ajaxOptions, thrownError){
                alert(thrownError);
            }
          });
        }
        else{
            $('#modal-table').html('');
            return false;
        }
    });
});

function addMapData(obj){
    var virtue_id = obj.value;
    var plugin_id = $("#modal-pluginid").val();
    console.log(plugin_id, virtue_id)
    $('#KbArticleMap').modal('toggle');
    $.ajax({
            type: "POST",
            url: '/nessus/plugin-map/',
            data: {
              'virtue_id': virtue_id,
              'plugin_id': plugin_id
            },
            dataType: 'json',
            success: function (response) {
                if (response.status == true){
                    $("#nessus-search").val('');
                    var plugin_td = "#plugin-"+plugin_id ;
                    $(plugin_td).html(virtue_id);

                 $.growl.notice(
                    {
                        title:"Success",
                        message: response.message
                    }
                );
                }
                else{
                     $.growl.error(
                        {
                            title: response.message,
                            message: response.errors
                        }
                    );
                } 
              
            },
            error: function (xhr, ajaxOptions, thrownError){
                alert(thrownError);
            }
        });
}


$(document).ready(function(){
    $("select.storage").change(function(){
        var selectedstorage = $(".storage option:selected").val();
        if (selectedstorage == "local"){
            $('#storage-table').hide();
            $('#id_s3_access_token').removeAttr('required');
            $('#id_s3_secret_access_token').removeAttr('required');
            $('#id_s3_bucket_name').removeAttr('required');
            $('#id_pre_signed_time_length').removeAttr('required');
        }
        else{
            $('#storage-table').show();
            $('#id_s3_access_token').prop('required','true');
            $('#id_s3_secret_access_token').prop('required','true');
            $('#id_s3_bucket_name').prop('required','true');
            $('#id_pre_signed_time_length').prop('required','true');
        }
    });

});


var nessus_plugin_array=[];
var plugindata = $("#nessus_plugin_array").val();
if (plugindata != ""){
    nessus_plugin_array.push(plugindata);
}
$(document).ready(function(){
    $('#nessus_plugin_save').prop('disabled',true);
    $('#nessus_plugin_id').keyup(function(){
        $('#nessus_plugin_save').prop('disabled', this.value == "" ? true : false);
    })
});
function nessusPlugInData(){
    var nessus_plugin_id = $("#nessus_plugin_id").val();
    nessus_plugin_array.push(nessus_plugin_id);
    $("#nessus_plugin_array").val(nessus_plugin_array);
    $("#nessus_plugin_id").val("");
    $('#nessus_plugin_save').prop('disabled',true);
    var plugins_array = $("#nessus_plugin_array").val();
    if (plugins_array){
        $('.new_article_button').prop('disabled',false);
    }
    else{
        $('.new_article_button').prop('disabled',true);
    }
}

$( ".plugin_id_value" ).click(function() {
    var plugin_id = $(this).val();
    nessus_plugin_array = []
    $("#nessus_plugin_id").val(plugin_id);
    $("#nessus_plugin_array").val("");
    $('#nessus_plugin_save').prop('disabled',false);
});

$(".new_article_button").click(function() {
    event.preventDefault();
    var plugin_array = $("#nessus_plugin_array").val();
    console.log('plugin_array',plugin_array);
    if (plugin_array){
        console.log('if');
        $('.new_article_button').prop('disabled',false);
    }
    else{
        console.log('else');
        $('.new_article_button').prop('disabled',true);
    }
    $(".new_article_button").unbind('click').click();
});

var burp_plugin_array=[];
var burpdata = $("#burp_plugin_array").val();
if (burpdata != ""){
    burp_plugin_array.push(burpdata);
}
$(document).ready(function(){
    $('#burp_plugin_save').prop('disabled',true);
    $('#burp_plugin_id').keyup(function(){
        $('#burp_plugin_save').prop('disabled', this.value == "" ? true : false);
    })
});
function burpPluginData(){
    var burp_plugin_id = $('#burp_plugin_id').val();
    burp_plugin_array.push(burp_plugin_id);
    $("#burp_plugin_array").val(burp_plugin_array);
    $("#burp_plugin_id").val("");
    $('#burp_plugin_save').prop('disabled',true);
    var burp_plugins_array = $("#burp_plugin_array").val();
    if (burp_plugins_array){
        $('.new_burp_article_button').prop('disabled',false);
    }
    else{
        $('.new_burp_article_button').prop('disabled',true);
    }
}

$( ".burp_plugin_value" ).click(function() {
    var burp_plugin_id = $(this).val();
    burp_plugin_array = []
    $("#burp_plugin_id").val(burp_plugin_id);
    $("#burp_plugin_array").val("");
    $('#burp_plugin_save').prop('disabled',false);
});

$(".new_burp_article_button").click(function() {
    event.preventDefault();
    var plugin_array = $("#burp_plugin_array").val();
    console.log('plugin_array',plugin_array);
    if (plugin_array){
        console.log('if');
        $('.new_burp_article_button').prop('disabled',false);
    }
    else{
        console.log('else');
        $('.new_burp_article_button').prop('disabled',true);
    }
    $(".new_burp_article_button").unbind('click').click();
});


function delete_host(host_id){
    $.ajax({
        url: '/delete/' + host_id + "/",
        type: "POST",
        dataType: 'json',
        success: function(response){
            if(response.status == true){

                $.growl.notice({
                    title: "Success",
                    message: response.message
                });
                setTimeout(function() {
                   window.location.href = "/home";
                }, 1000);
                
            }
            else {
                $.growl.error({
                    title: "Oops!",
                    message: response.message
                });
            }
        },
        error: function(xhr, ajaxOption, thrownError){
            $.growl.error({
                    title: "Oops!",
                    message: thrownError
                });
        }
    });
}

function retest_vulnerability(vul_id){
    var retest_form_action = '/vulnerabilities/' + vul_id + '/';
    $('.retest_vul_note_class').val("");
    $('.retest_vul_id').val(vul_id);
    $('.retest-form-action').attr('action', retest_form_action)
}

/* To copy aws assets in cloud page */

function copyToClipboard(tokenType, counter) {
    var myTooltip = ".tool-tip-"+tokenType+"-"+counter;
    if (tokenType == "access"){
        var input_id = "#aws_access_token_input_"+counter;
    }else{
        var input_id = "#aws_secret_token_input_"+counter;
    }
    var tooltip = $(myTooltip);
    $(".tool-tip-token").html("Copy to clipboard")
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

    tooltip.html("Copied!");
}
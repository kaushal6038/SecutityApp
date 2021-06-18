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

//	// Minify menu on menu_minifier click
//	querySelector('.collapse-menu').onclick = function () {
//		nav.classList.toggle('vertical-nav-sm');
//		$('.dashboard-wrapper').toggleClass(('dashboard-wrapper-lg'), 200);
//		$("i", this).toggleClass("icon-menu2 icon-cross2");
//	};

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

$(document).ready(function(){
    $('#load').prop('disabled',true);
    $('#ipaddress').keyup(function(){
        $('#load').prop('disabled', this.value == "" ? true : false);
        resetButton();
    })
    $('#load').click(function () {
        var btn = $(this)
        btn.button('loading')
    })
});


var csrftoken = jQuery("[name=csrfmiddlewaretoken]").val();
    function csrfSafeMethod(method) {
        return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });


$(document).ready(function() {
    $('#pleaf-datatable').DataTable( {
        "paging":   false,
        dom: 'Bfrtip',
        buttons: [
            'copy',
            {
               extend: 'csv',
               exportOptions: {
                    columns: [0,1,2,3] // indexes of the columns that should be printed,
                }                      // Exclude indexes that you don't want to print.
            },
            'excel', 'pdf', 'print'
        ]
    } );
} );

function checkStatus(status){
    $.ajax({
        url: '/api/toggle_activity',
        type: 'POST',
        dataType: 'json',
        success: function(response){
        if (response == true) {
            $('#status').removeClass('btn-danger');
            $('#status').addClass('btn-success');
            $('#status').val('True');
            $('#status').text('Scanning is active. Click to stop');
        }
        else if(response == false) {
            $('#status').removeClass('btn-success');
            $('#status').addClass('btn-danger');
            $('#status').val('False');
            $('#status').text('Scanning is not active. Click to start');
            }
        else {
        	$.growl.error({title:"Error!", message: "Unable to change status"});
        	} 
    	},
        error:function (xhr, ajaxOptions, thrownError){
        	$.growl.error({title:"Error!", message: "Unable to change status"});
        }
     });
}

$(document).ready(function(){
	
  	all_types = ['.activity_age_ago', '.age_ago', '.service_age'];
  	for (x in all_types){
  		if (all_types[x] == '.activity_age_ago'){
			moment.locale('en', {
	    	relativeTime: {
		    	future: 'in %s',
				past: '%s',
				s:  's',
				ss: '%ss',
				m:  '%dm',
				mm: '%dm',
				h:  '%dh',
				hh: '%dh',
				d:  '%dd',
				dd: '%dd',
				M:  '%dM',
				MM: '%dM',
				y:  '%dY',
				yy: '%dY'
	    	}
			});
		}else{
			moment.locale('en', {
	    	relativeTime: {
		    	future: 'in %s',
				past: '%s ago',
				s:  'seconds',
				ss: '%s seconds',
				m:  '%d minute',
				mm: '%d minutes',
				h:  '%d hour',
				hh: '%d hours',
				d:  '%d day',
				dd: '%d days',
				M:  '%d month',
				MM: '%d months',
				y:  '%d year',
				yy: '%d years'
	    	}
			});
		}
  		var time_ago = $(all_types[x]);
		var counter = time_ago.length;
		time_format = 'MMMM Do YYYY, h:mm:ss a';
		if (all_types[x] == '.activity_age_ago'){
			time_format = 'YYYY-MM-Do, h:mm:ss a';
		}
		for (i in time_ago){
			var result = moment(time_ago[i].innerHTML, time_format).fromNow();
			time_ago[i].innerHTML = result;
		}
	}
});

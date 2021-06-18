

// Markers on the world map

function getScalling(country) {
	var coords = countryCoords[country]
	return {lat: coords[0], lng: coords[1], scale: 3, animate: true}
}


$(function(data){
 	var plotlist = []
 	$.ajax({
        url: '/whois-map/',
        type: 'GET',
        dataType: 'json',

        success: function(response){
        	mapdata = response.mapdata
        	country_code = response.country_code
        },
        error:function (xhr, ajaxOptions, thrownError){
            alert(thrownError);
            mapdata = []
            country_code = []
        },
        async: false
    });
    $.each(JSON.parse(mapdata), function (i, item){
 		var latlng = {};
 		latlng.latLng = [item.fields.latitude, item.fields.longitude]
 		latlng.name = item.fields.asn_description
 		plotlist.push(latlng);
 	});
	$('#world-map-markers').vectorMap({

		map: 'world_mill_en',
		scaleColors: ['#6FB4CE', '#A9BD7A'],
		normalizeFunction: 'polynomial',
		hoverOpacity: 0.7,
		hoverColor: false,
		zoomOnScroll: true,
		markerStyle: {
			initial: {
				fill: '#E04747',
				stroke: '#FFFFFF',
				r: 4
			}
		},
	onRegionTipShow: function (e, label, code) {
    e.preventDefault();
	},
		zoomMin: 1,
		hoverColor: true,
		series: {
			regions: [{
				values: gdpData,
				scale: ['#89A4C1', '#959AB8'],
				attribute: 'fill',
				normalizeFunction: 'polynomial'
			}]
		},
		backgroundColor: '#2a3039',
		markers: plotlist,
	});
	var mapObj = $('#world-map-markers').vectorMap('get', 'mapObject');
	if (plotlist.length == 1){
		plotelem = plotlist[0]
		focus = {scale:3, lat: plotelem.latLng[0], lng: plotelem.latLng[1], animate: true}
		mapObj.setFocus(focus)
	}
	else {
		if (country_code.length == 1) {
		    var coords = getScalling(country_code[0])
		    mapObj.setFocus(coords)
		}
		else if (country_code.length > 1){
			mapObj.setFocus({
				regions: country_code,
				animate: true
			})
		}

	}
});

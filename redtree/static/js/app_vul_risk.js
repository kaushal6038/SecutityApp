$(document).ready(function() {
  $.ajax({
    type: "GET",
    async: false,
    url: "/charts/application/",
    success: function(response) {
      app_vul = response.app_vul;
    }
  });
  function drawAppVulnerabilitiesChart(){
    function constant$10(x) {
      return function constant() {
        return x;
      };
    }
    function none$1(series, order) {
      if (!((n = series.length) > 1)) return;
      for (var i = 1, j, s0, s1 = series[order[0]], n, m = s1.length; i < n; ++i) {
        s0 = s1, s1 = series[order[i]];
        for (j = 0; j < m; ++j) {
          s1[j][1] += s1[j][0] = isNaN(s0[j][1]) ? s0[j][0] : s0[j][1];
        }
      }
    }

    function stackValue(d, key) {
      return d[key];
    }

    function none$2(series) {
      var n = series.length, o = new Array(n);
      while (--n >= 0) o[n] = n;
      return o;
    }

    var slice$6 = Array.prototype.slice;

    function stack() {
        var keys = constant$10([]),
            order = none$2,
            offset = none$1,
            value = stackValue;

        function stack(data) {
          var kz = keys.apply(this, arguments),
              i,
              m = data.length,
              n = kz.length,
              sz = new Array(n),
              oz;

          for (i = 0; i < n; ++i) {
            for (var ki = kz[i], si = sz[i] = new Array(m), j = 0, sij; j < m; ++j) {
              si[j] = sij = [0, +value(data[j], ki, j, data)];
              sij.data = data[j];
            }
            si.key = ki;
          }

          for (i = 0, oz = order(sz); i < n; ++i) {
            sz[oz[i]].index = i;
          }

          offset(sz, oz);
          return sz;
        }

        stack.keys = function(_) {
          return arguments.length ? (keys = typeof _ === "function" ? _ : constant$10(slice$6.call(_)), stack) : keys;
        };

        stack.value = function(_) {
          return arguments.length ? (value = typeof _ === "function" ? _ : constant$10(+_), stack) : value;
        };

        stack.order = function(_) {
          return arguments.length ? (order = _ == null ? none$2 : typeof _ === "function" ? _ : constant$10(slice$6.call(_)), stack) : order;
        };

        stack.offset = function(_) {
          return arguments.length ? (offset = _ == null ? none$1 : _, stack) : offset;
        };

        return stack;
      }
    var stc = $('#appvulnerabilitiesChart');
    var widther = stc.width();
    var margin = {top: 5, right: 120, bottom: 90, left: 28},
        width = widther - margin.left - margin.right + 110,
        height = 250 - margin.top - margin.bottom ;
      
    $("#appvulnerabilitiesChart").empty();

    var svg = d3.select("#appvulnerabilitiesChart").append("svg")
          .attr("width", width + margin.left + margin.right)
          .attr("height", height + margin.top + margin.bottom);

    var g = svg.append("g").attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    var x = d3.scale.ordinal()
          .rangeRoundBands([0, width], 0.1)

    var y = d3.scale.linear()
          .rangeRound([height, 0]);

    var z = d3.scale.ordinal()
          .range([
            riskColors.low,            
            riskColors.medium,
            riskColors.high,            
            riskColors.critical
            ]);

    var stack = stack();
    var data = [];
    for(var v in app_vul)
    {
      var d = app_vul[v];
      console.log('vvvvvv',v)
      data.push({"Date": d.Date, "Low": d.Low, 
        "Medium": d.Medium, "High": d.High, "Critical": d.Critical});
    }
    var tip = d3.tip()
      .attr('class', 'd3-tip')
      .offset([-10, 0])
      .html(function(d) {
      var tooltip = '<div class="c3-tooltip-container"><table class="c3-tooltip"><tbody>' 
          +'<tr><th colspan="2">'
          +d.data.Date
          +'</th></tr>'
          +'<tr class="c3-tooltip-name-Critical">'
          +'<td class="name"><span style="background-color:#BF3D47"></span>Critical</td>'
          +'<td class="value">'
          +d.data.Critical
          +'</td></tr>'
          +'<tr class="c3-tooltip-name-High">'
          +'<td class="name"><span style="background-color:#A1665F"></span>High</td>'
          +'<td class="value">'
          +d.data.High
          +'</td></tr>'
          +'<tr class="c3-tooltip-name-Medium">'
          +'<td class="name"><span style="background-color:#D9A66D"></span>Medium</td>'
          +'<td class="value">'
          +d.data.Medium
          +'</td></tr>'
          +'<tr class="c3-tooltip-name-Low">'
          +'<td class="name"><span style="background-color:#337ab7"></span>Low</td>'
          +'<td class="value">'
          +d.data.Low
          +'</td></tr>'
          +'</tbody></table></div>'
      return tooltip;
      })

    svg.call(tip);

    // fix pre-processing
    var keys = [];
    for (key in data[0]){
      if (key != "Date")
        keys.push(key);
    }
    data.forEach(function(d){
      d.total = 0;
      keys.forEach(function(k){
        d.total += parseInt(d[k]);
      })
    });
    x.domain(data.map(function(d) {
      return d.Date;
    }));
    
    y.domain([0, d3.max(data, function(d) {
      return d.total;
    })]).nice();

    z.domain(keys);

    g.selectAll(".serie")
      .data(stack.keys(keys)(data))
      .enter().append("g")
        .attr("class", "serie")
        .attr("fill", function(d) { return z(d.key); })
      .selectAll("rect")
      .data(function(d) { return d; })
      .enter().append("rect")
        .attr("x", function(d) { return x(d.data.Date); })
        .attr("y", function(d) { return y(d[1]); })
        .attr("height", function(d) { return y(d[0]) - y(d[1]); })
        .attr("width", x.rangeBand())
        .on('mouseover', tip.show)
        .on('mouseout', tip.hide);
    g.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + height + ")")
        .call(d3.svg.axis()
        .scale(x)
        .orient("bottom")
        .tickValues([data[0].Date,data[29].Date]));
    g.append("g")
        .attr("class", "axis y-axis")
        .call(d3.svg.axis().scale(y).orient("left").ticks(5, "s"))
      .append("text")
        .attr("x", 5)
        .attr("y", y(y.ticks(5).pop()))
        .attr("dy", "0.35em")
        .attr("text-anchor", "start")
        .attr("fill", "#000")
        .text("");

  var legend = g.append("g")
    .attr("font-family", "sans-serif")
    .attr("font-size", 10)
    .attr("text-anchor", "end")
    .selectAll("g")
    .data(keys.slice().reverse())
    .enter().append("g")

  .attr("transform", function(d, i) {
      var center_width = (width/2);
        if (i==0){
              return "translate(-" + ((center_width-50) + i *70) +"," + "200)";
            }
        else if (i==1){
          return "translate(-" + ((center_width-50) + i *70) +"," + "200)";
        }
        else if (i==2){
          return "translate(-" + ((center_width-60) + i *70) +"," + "200)";
        }
        else if (i==3){
          return "translate(-" + ((center_width-60) + i *70) +"," + "200)";
        }
        else{
          return "translate(-" + ((center_width-50) + i *70) +"," + "200)";
        }
    });

  legend.append("rect")
      .attr("x", function(d, i) {
          if (i==0){
            return (width - 19); 
          }
          else if (i==1){
            return (width - 9);
          }
          else if (i==2){
            return (width - 25);
          }
          else if (i==3){
            return (width - 7);
          }
          else{
             return (width - 19);
          }
      })
      .attr("width", 12)
      .attr("height", 3)
      .attr("fill", z);

  legend.append("text")
      .attr("x", width + 35)
      .attr("y", 1.5)
      .attr("dy", "0.32em")
      .text(function(d) { return d; });
  }
drawAppVulnerabilitiesChart();
window.addEventListener("resize", drawAppVulnerabilitiesChart);
});


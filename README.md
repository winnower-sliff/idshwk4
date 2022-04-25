# idshwk4
```zeek
event http_reply(c: connection, version: string, code: count, reason: string)
{

	SumStats::observe("responses",  						# 观察器名称
                      SumStats::Key($str="all",$host=c$id$resp_h),		# 添加键，可用key$host访问
                      SumStats::Observation($num=1));		# 统计数
	if(code==404)
	{
		SumStats::observe("responses",  						# 观察器名称
	                      SumStats::Key($str="404",$host=c$id$resp_h),		# 添加键，可用key$host访问
	                      SumStats::Observation($num=1,$str=c$http$uri));		# 统计数
	}
	
}

type sumUni:record{sum:double;unique:double;};
global re:table[SumStats::Key] of sumUni;

event zeek_init()
    {
    
    local resp = SumStats::Reducer($stream="responses", 			# 抓到观察器
                                 $apply=set(SumStats::SUM,SumStats::UNIQUE));			# 使用集合设置统计方法

    SumStats::create([$name = "finding scanners",
                      $epoch = 10min,
                      $reducers = set(resp),
                      $epoch_result(ts:time,key: SumStats::Key, result: SumStats::Result) =
                        {
                            re[key]=[$sum=result["responses"]$sum,$unique=result["responses"]$unique];
                        },
                      $epoch_finished(ts:time)=
                    	{
                    		# print re;
                    		
				for(i in re)
				{
					if(i$str=="404" && re[i]$sum>2)
					{
						local sumOfAll:double=re[SumStats::Key($str="all",$host=i$host)]$sum;
						if(re[i]$sum*5>sumOfAll && re[i]$unique*2>re[i]$sum)
							print fmt("%s is a scanner with %.0f scan attemps on %.0f urls",i$host,re[i]$sum,re[i]$unique);
					}
				}
                  
                  
                        	# for(i in re)delete re[i];
                    	}
                      ]);
    }
```

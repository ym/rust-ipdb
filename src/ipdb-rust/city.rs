use serde::Serialize;
#[derive(Debug, Serialize)]
pub struct CityInfo<'a> {
    pub country_name: &'a str,
    pub region_name: &'a str,
    pub city_name: &'a str,
    pub owner_domain: &'a str,
    pub isp_domain: &'a str,
    pub latitude: &'a str,
    pub longitude: &'a str,
    pub timezone: &'a str,
    pub utcoffset: &'a str,
    pub china_admin_code: &'a str,
    pub idd_code: &'a str,
    pub country_code: &'a str,
    pub continent_code: &'a str,
}

impl<'a> From<Vec<&'a str>> for CityInfo<'a> {
    fn from(buff: Vec<&'a str>) -> Self {
        CityInfo {
            country_name: if buff.len() > 0 { buff[0] } else { "" },
            region_name: if buff.len() > 1 { buff[1] } else { "" },
            city_name: if buff.len() > 2 { buff[2] } else { "" },
            owner_domain: if buff.len() > 3 { buff[3] } else { "" },
            isp_domain: if buff.len() > 4 { buff[4] } else { "" },
            latitude: if buff.len() > 5 { buff[5] } else { "" },
            longitude: if buff.len() > 6 { buff[6] } else { "" },
            timezone: if buff.len() > 7 { buff[7] } else { "" },
            utcoffset: if buff.len() > 8 { buff[8] } else { "" },
            china_admin_code: if buff.len() > 9 { buff[9] } else { "" },
            idd_code: if buff.len() > 10 { buff[10] } else { "" },
            country_code: if buff.len() > 11 { buff[11] } else { "" },
            continent_code: if buff.len() > 12 { buff[12] } else { "" },
        }
    }
}
